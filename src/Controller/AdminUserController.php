<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Service\AdminAccountService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

#[Route('/api/admin')]
final class AdminUserController extends AbstractController
{
    public function __construct(
        private readonly EntityManagerInterface $em,
        private readonly AdminAccountService $accounts,
        private readonly UserPasswordHasherInterface $hasher,
    ) {}

    private function actor(): User
    {
        $user = $this->getUser();
        if (!$user instanceof User || $user->isDisabled() || !in_array('ROLE_ADMIN', $user->getRoles(), true)) {
            throw $this->createAccessDeniedException();
        }
        return $user;
    }

    private function response(array $data, int $status = 200): JsonResponse
    {
        return new JsonResponse($data, $status, ['Cache-Control' => 'private, no-store']);
    }

    private function body(Request $request): array
    {
        if (strlen($request->getContent()) > 8000) return [];
        try {
            $json = json_decode($request->getContent(), true, 12, JSON_THROW_ON_ERROR);
            return is_array($json) ? $json : [];
        } catch (\JsonException) { return []; }
    }

    private function checkWrite(Request $request): ?JsonResponse
    {
        $actor = $this->actor();
        $expected = (string) $request->headers->get('X-Admin-Actor-Id', '');
        if ($expected !== '' && !hash_equals($actor->getId(), $expected)) {
            return $this->response(['error' => 'La session a change pendant cette action. Reessayez.', 'code' => 'actor_changed'], 409);
        }
        if (!$this->isCsrfTokenValid('vault_api', (string) $request->headers->get('X-CSRF-Token', ''))) {
            return $this->response(['error' => 'Jeton de securite expire.', 'code' => 'csrf_invalid'], 403);
        }
        return null;
    }

    private function getTarget(string $id): User
    {
        $user = $this->em->getRepository(User::class)->find($id);
        if (!$user instanceof User) throw $this->createNotFoundException('Compte introuvable.');
        return $user;
    }

    private function validEmail(string $email): bool
    {
        return strlen($email) <= 180 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    #[Route('/users', name: 'ds_admin_users_list', methods: ['GET'])]
    public function list(Request $request): JsonResponse
    {
        $this->actor();
        $q = strtolower(trim((string) $request->query->get('q', '')));
        if (strlen($q) > 100) return $this->response(['error' => 'Recherche trop longue.'], 422);
        $page = min(10000, max(1, (int) $request->query->get('page', 1)));
        $conn = $this->em->getConnection();
        $filter = '';
        $params = [];
        if ($q !== '') {
            // Escape literal SQL LIKE wildcards to avoid unexpectedly broad matches.
            $filter = " WHERE LOWER(email) LIKE :q ESCAPE '!'";
            $params['q'] = '%'.str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $q).'%';
        }
        $total = (int) $conn->fetchOne('SELECT COUNT(*) FROM vault_user'.$filter, $params);
        $rows = $conn->fetchAllAssociative(
            'SELECT id, email, roles, disabled_at, must_change_password, created_at, last_login_at, vault_salt, totp_secret,
                sharing_public_key FROM vault_user'.$filter.' ORDER BY LOWER(email) ASC LIMIT 25 OFFSET '.(($page-1)*25), $params
        );
        return $this->response(['total' => $total, 'page' => $page, 'pageSize' => 25, 'users' => array_map(function(array $row): array {
            $roles = json_decode((string) $row['roles'], true);
            return [
                'id' => $row['id'], 'email' => $row['email'],
                'admin' => is_array($roles) && in_array('ROLE_ADMIN', $roles, true),
                'disabled' => $row['disabled_at'] !== null,
                'mustChangePassword' => (bool) $row['must_change_password'],
                'vaultInitialized' => $row['vault_salt'] !== null,
                'sharingEnabled' => $row['sharing_public_key'] !== null,
                'twoFactor' => $row['totp_secret'] !== null,
                'createdAt' => $row['created_at'], 'lastLoginAt' => $row['last_login_at'],
            ];
        }, $rows)]);
    }

    #[Route('/metrics', name: 'ds_admin_metrics', methods: ['GET'])]
    public function metrics(): JsonResponse
    {
        $this->actor();
        $db = $this->em->getConnection();
        $total = (int) $db->fetchOne('SELECT COUNT(*) FROM vault_user');
        $disabled = (int) $db->fetchOne('SELECT COUNT(*) FROM vault_user WHERE disabled_at IS NOT NULL');
        $shares = (int) $db->fetchOne('SELECT COUNT(*) FROM vault_share WHERE revoked_at IS NULL AND declined_at IS NULL');
        $entries = (int) $db->fetchOne('SELECT COUNT(*) FROM vault_entry');
        return $this->response(['accounts' => $total, 'active' => $total-$disabled, 'disabled' => $disabled, 'shares' => $shares, 'encryptedItems' => $entries]);
    }

    #[Route('/audit', name: 'ds_admin_audit', methods: ['GET'])]
    public function audit(): JsonResponse
    {
        $this->actor();
        $rows = $this->em->getConnection()->fetchAllAssociative(
            'SELECT actor_email, subject_email, action, details, created_at FROM vault_admin_audit ORDER BY created_at DESC, id DESC LIMIT 100'
        );
        return $this->response(['events' => array_map(static fn (array $row): array => [
            'actor' => $row['actor_email'], 'subject' => $row['subject_email'],
            'action' => $row['action'], 'date' => $row['created_at'],
            'details' => json_decode((string)$row['details'], true),
        ], $rows)]);
    }

    #[Route('/invitations-overview', name: 'ds_admin_invitation_overview', methods: ['GET'])]
    public function invitationOverview(): JsonResponse
    {
        $this->actor();
        $rows = $this->em->getConnection()->fetchAllAssociative(
            'SELECT i.id, o.email AS owner_email, i.recipient_email, i.company_folder, i.expires_at, i.created_at, i.revoked_at, i.redeemed_at, c.imported_at
             FROM vault_invitation i
             JOIN vault_user o ON o.id = i.owner_id
             LEFT JOIN vault_contribution c ON c.invitation_id = i.id
             ORDER BY i.created_at DESC LIMIT 200'
        );
        return $this->response(['invitations'=>array_map(static fn(array $r):array=>[
            'id'=>$r['id'], 'owner'=>$r['owner_email'], 'recipient'=>$r['recipient_email'],
            'folder'=>$r['company_folder'], 'createdAt'=>$r['created_at'], 'expiresAt'=>$r['expires_at'],
            'revoked'=>$r['revoked_at'] !== null, 'used'=>$r['redeemed_at'] !== null,
            'imported'=>$r['imported_at'] !== null,
        ], $rows)]);
    }

    #[Route('/users', name: 'ds_admin_users_create', methods: ['POST'])]
    public function create(Request $request): JsonResponse
    {
        if ($error = $this->checkWrite($request)) return $error;
        $actor = $this->actor();
        $data = $this->body($request);
        $email = strtolower(trim((string) ($data['email'] ?? '')));
        if (!$this->validEmail($email) || !is_bool($data['admin'] ?? null)) {
            return $this->response(['error' => 'E-mail ou rôle invalide.'], 422);
        }
        if ($this->em->getRepository(User::class)->findOneBy(['email' => $email])) {
            return $this->response(['error' => 'Cette adresse est déjà utilisée.'], 409);
        }
        // Token a usage initial, never saved in plaintext or logged.
        $temporaryPassword = rtrim(strtr(base64_encode(random_bytes(27)), '+/', '-_'), '=');
        $user = new User(Uuid::v4()->toRfc4122(), $email);
        $user->setPasswordHash($this->hasher->hashPassword($user, $temporaryPassword));
        $user->requirePasswordChange();
        if ($data['admin']) $user->grantAdmin();
        $db = $this->em->getConnection();
        try {
            $db->beginTransaction();
            $this->em->persist($user);
            $this->em->flush();
            $this->accounts->audit($actor->getEmail(), $email, 'user.created', ['admin' => $data['admin']]);
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            return $this->response(['error' => 'Création impossible, vérifiez l’adresse.'], 409);
        }
        return $this->response(['ok' => true, 'id' => $user->getId(), 'email' => $email,
            'temporaryPassword' => $temporaryPassword, 'mustChangePassword' => true], 201);
    }

    #[Route('/users/{id}', name: 'ds_admin_users_update', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['PATCH'])]
    public function update(string $id, Request $request): JsonResponse
    {
        if ($error = $this->checkWrite($request)) return $error;
        $actor = $this->actor();
        $user = $this->getTarget($id);
        $data = $this->body($request);
        $allowed = ['email', 'admin', 'disabled'];
        if (!$data || array_diff(array_keys($data), $allowed)) {
            return $this->response(['error' => 'Modification invalide.'], 422);
        }
        $oldEmail = $user->getEmail();
        $changed = [];
        if (array_key_exists('email', $data)) {
            $email = strtolower(trim((string)$data['email']));
            if (!$this->validEmail($email)) return $this->response(['error' => 'E-mail invalide.'], 422);
            if ($email !== $oldEmail) {
                if ($user->getId() === $actor->getId()) return $this->response(['error' => 'Pour modifier votre propre e-mail, utilisez une commande sécurisée.'], 403);
                if ($this->em->getRepository(User::class)->findOneBy(['email' => $email])) return $this->response(['error' => 'Adresse déjà attribuée.'], 409);
                $user->setEmail($email);
                $changed['email'] = ['old' => $oldEmail, 'new' => $email];
            }
        }
        if (array_key_exists('admin', $data)) {
            if (!is_bool($data['admin'])) return $this->response(['error' => 'Rôle invalide.'], 422);
            $wasAdmin = in_array('ROLE_ADMIN', $user->getRoles(), true);
            if ($wasAdmin !== $data['admin']) {
                if ($wasAdmin && !$data['admin']) {
                    if ($user->getId() === $actor->getId()) return $this->response(['error' => 'Vous ne pouvez pas vous retirer votre propre rôle.'], 403);
                    if ($this->accounts->otherAdminsCount($user->getId()) === 0) return $this->response(['error' => 'Dernier administrateur actif.'], 409);
                    $user->revokeAdmin();
                } else {
                    // Les comptes administrateurs ne doivent pas remplacer des comptes coffre existants :
                    // cela rendrait leurs donnees personnelles inaccessibles depuis /vault.
                    if (!$this->accounts->canResetPassword($user)) {
                        return $this->response(['error' => 'Ce compte possède déjà un coffre ou des partages. Créez un compte administrateur distinct.'], 409);
                    }
                    $user->grantAdmin();
                }
                $changed['admin'] = $data['admin'];
            }
        }
        if (array_key_exists('disabled', $data)) {
            if (!is_bool($data['disabled'])) return $this->response(['error' => 'Statut invalide.'], 422);
            if ($user->isDisabled() !== $data['disabled']) {
                if ($data['disabled']) {
                    if ($user->getId() === $actor->getId()) return $this->response(['error' => 'Impossible de suspendre votre propre compte.'], 403);
                    if (in_array('ROLE_ADMIN', $user->getRoles(), true) && $this->accounts->otherAdminsCount($user->getId()) === 0) {
                        return $this->response(['error' => 'Impossible de suspendre le dernier administrateur actif.'], 409);
                    }
                }
                $user->setDisabled($data['disabled']);
                $changed['disabled'] = $data['disabled'];
            }
        }
        if (!$changed) return $this->response(['ok' => true, 'changed' => false]);
        $db = $this->em->getConnection();
        try {
            $db->beginTransaction();
            $this->em->flush();
            // Toute modification identitaire ou des permissions revoque les sessions de l'extension.
            // Les sessions navigateur sont revalidees via AccountPolicySubscriber.
            $db->executeStatement('DELETE FROM vault_extension_session WHERE owner_id=:id', ['id' => $id]);
            $this->accounts->audit($actor->getEmail(), $oldEmail, 'user.updated', $changed);
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            return $this->response(['error' => 'Modification impossible.'], 409);
        }
        return $this->response(['ok' => true, 'changed' => true]);
    }

    #[Route('/users/{id}/reset-initial-password', name: 'ds_admin_users_reset', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['POST'])]
    public function resetInitialPassword(string $id, Request $request): JsonResponse
    {
        if ($error = $this->checkWrite($request)) return $error;
        $actor = $this->actor();
        $user = $this->getTarget($id);
        if ($actor->getId() === $user->getId()) return $this->response(['error' => 'Votre propre mot de passe ne peut pas être réinitialisé ici.'], 403);
        if (!$this->accounts->canResetPassword($user)) return $this->response(['error' => 'Coffre ou données de partage déjà initialisés : réinitialisation interdite pour protéger le chiffrement.'], 409);
        $password = rtrim(strtr(base64_encode(random_bytes(27)), '+/', '-_'), '=');
        $user->setPasswordHash($this->hasher->hashPassword($user, $password));
        $user->requirePasswordChange();
        $db = $this->em->getConnection();
        $db->beginTransaction();
        try {
            $this->em->flush();
            $db->executeStatement('DELETE FROM vault_extension_session WHERE owner_id=:id', ['id'=>$id]);
            $this->accounts->audit($actor->getEmail(), $user->getEmail(), 'user.initial_password_reset');
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            return $this->response(['error'=>'Réinitialisation impossible.'],500);
        }
        return $this->response(['ok'=>true, 'email'=>$user->getEmail(), 'temporaryPassword'=>$password]);
    }

    #[Route('/users/{id}/deletion-preview', name: 'ds_admin_users_preview', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['GET'])]
    public function preview(string $id): JsonResponse
    {
        $this->actor();
        $user = $this->getTarget($id);
        return $this->response(['email'=>$user->getEmail(), 'counts'=>$this->accounts->userCounts($id)]);
    }

    #[Route('/users/{id}', name: 'ds_admin_users_delete', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['DELETE'])]
    public function delete(string $id, Request $request): JsonResponse
    {
        if ($error = $this->checkWrite($request)) return $error;
        $actor = $this->actor();
        $user = $this->getTarget($id);
        $email = $user->getEmail();
        $data = $this->body($request);
        if (!is_string($data['confirmEmail'] ?? null) || !hash_equals($email, strtolower(trim($data['confirmEmail'])))) {
            return $this->response(['error'=>'Tapez l’adresse exacte du compte à supprimer.'],422);
        }
        try {
            $counts = $this->accounts->deleteUser($user, $actor, $email);
            $this->em->clear();
            return $this->response(['ok' => true, 'counts' => $counts]);
        } catch (\DomainException $e) {
            return $this->response(['error'=>$e->getMessage()],409);
        } catch (\Throwable $e) {
            return $this->response(['error'=>'Suppression annulée. Consultez les journaux serveur.'],500);
        }
    }
}
