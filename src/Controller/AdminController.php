<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Service\AdminAccountService;
use App\Entity\VaultInvitation;
use App\Entity\VaultContribution;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class AdminController extends AbstractController
{
    private function user(): User
    {
        $user = $this->getUser();
        if (!$user instanceof User || !in_array('ROLE_ADMIN', $user->getRoles(), true)) throw $this->createAccessDeniedException();
        return $user;
    }
    /** L'authentification Symfony et ROLE_ADMIN protegent toutes les routes admin.
     *  Le 2FA, s'il est active, est impose globalement par TwoFactorSubscriber.
     */
    private function ready(Request $request): bool
    {
        $this->user();
        return true;
    }
    private function csrf(Request $r): bool { return $this->isCsrfTokenValid('vault_api', (string)$r->headers->get('X-CSRF-Token')); }
    /** Toujours valider les privileges du compte actuellement authentifie.
     *  L'en-tete d'acteur evite un changement de session entre GET csrf et POST.
     *  Les clients historiques sans cet en-tete restent proteges par le CSRF.
     */
    private function writeError(Request $r): ?JsonResponse
    {
        $actor = $this->user();
        $expected = (string) $r->headers->get('X-Admin-Actor-Id', '');
        if ($expected !== '' && !hash_equals($actor->getId(), $expected)) {
            return $this->out(['error' => 'Le compte administrateur a change pendant cette action. Reessayez.', 'code' => 'actor_changed'], 409);
        }
        if (!$this->csrf($r)) {
            return $this->out(['error' => 'Jeton de securite expire.', 'code' => 'csrf_invalid'], 403);
        }
        return null;
    }

    private function readJsonBody(Request $r, int $limit = 8000): array
    {
        if (strlen($r->getContent()) > $limit) return [];
        $value = json_decode($r->getContent(), true, 12);
        return is_array($value) ? $value : [];
    }
    private function out(array $body, int $status = 200): JsonResponse
    {
        return new JsonResponse($body, $status, ['Cache-Control' => 'private, no-store, max-age=0']);
    }
    /**
     * Renouvelle le jeton de l'onglet administrateur apres un changement de
     * session (plusieurs comptes Edge ou onglet reste ouvert). L'API et le
     * tableau de bord exigent tous deux ROLE_ADMIN.
     */
    #[Route('/api/admin/csrf', name: 'ds_admin_csrf', methods: ['GET'])]
    public function adminCsrf(Request $request, CsrfTokenManagerInterface $csrf): JsonResponse
    {
        $this->ready($request);
        return $this->out([
            'csrfToken' => (string) $csrf->getToken('vault_api')->getValue(),
            'actorId' => $this->user()->getId(),
            'actorEmail' => $this->user()->getEmail(),
        ]);
    }

    #[Route('/api/admin/overview', name: 'ds_admin_overview', methods: ['GET'])]
    public function overview(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->ready($request)) return $this->out(['error'=>'Accès administrateur à revalider.'], 403);
        $db = $em->getConnection();
        $users = $db->fetchAllAssociative('SELECT id, email, roles FROM vault_user ORDER BY email ASC LIMIT 500');
        $result = [];
        foreach ($users as $row) {
            $roles = json_decode((string) $row['roles'], true);
            $result[] = ['email'=>(string)$row['email'], 'admin'=>is_array($roles) && in_array('ROLE_ADMIN', $roles, true)];
        }
        $shares = $db->fetchAllAssociative('SELECT s.id, s.scope_type, s.created_at, s.accepted_at, s.revoked_at, o.email AS owner_email, r.email AS recipient_email FROM vault_share s JOIN vault_user o ON o.id=s.owner_id JOIN vault_user r ON r.id=s.recipient_id ORDER BY s.created_at DESC LIMIT 200');
        return $this->out(['users'=>$result, 'shares'=>array_map(static fn(array $s)=>[
            'id'=>$s['id'], 'scope'=>$s['scope_type'], 'owner'=>$s['owner_email'],
            'recipient'=>$s['recipient_email'], 'createdAt'=>$s['created_at'],
            'accepted'=>$s['accepted_at']!==null, 'revoked'=>$s['revoked_at']!==null,
        ], $shares)]);
    }

    #[Route('/api/admin/shares/{id}/revoke', name: 'ds_admin_share_revoke', requirements:['id'=>'[0-9a-fA-F-]{36}'], methods:['POST'])]
    public function revokeShare(string $id, Request $request, EntityManagerInterface $em, AdminAccountService $accounts): JsonResponse
    {
        if ($error = $this->writeError($request)) return $error;
        $db = $em->getConnection();
        $share = $db->fetchAssociative('SELECT r.email AS recipient_email FROM vault_share s JOIN vault_user r ON s.recipient_id=r.id WHERE s.id=:id AND s.revoked_at IS NULL', ['id'=>$id]);
        if (!$share) return $this->out(['error'=>'Partage introuvable ou déjà révoqué.'],404);
        $db->beginTransaction();
        try {
            $changed = $db->executeStatement('UPDATE vault_share SET revoked_at=:now, encrypted_bundle=:empty WHERE id=:id AND revoked_at IS NULL',
                ['now'=>gmdate('Y-m-d H:i:s'), 'empty'=>'{}', 'id'=>$id]);
            if ($changed !== 1) { $db->rollBack(); return $this->out(['error'=>'Partage déjà révoqué.'],409); }
            $accounts->audit($this->user()->getEmail(), (string)$share['recipient_email'], 'share.revoked', ['shareId'=>$id]);
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            return $this->out(['error'=>'Révocation impossible.'],500);
        }
        return $this->out(['ok'=>true]);
    }

    #[Route('/api/admin/status', name: 'ds_admin_status', methods: ['GET'])]
    public function status(Request $request): JsonResponse
    {
        return $this->out(['unlocked' => $this->ready($request)]);
    }
    #[Route('/api/admin/invitations', name: 'ds_admin_invites', methods: ['GET'])]
    public function invitations(Request $r, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->ready($r)) return $this->out(['error'=>'Accès administrateur à revalider.'],403);
        $rows = $em->getRepository(VaultInvitation::class)->findBy(['owner'=>$this->user()], ['createdAt'=>'DESC'], 150);
        return $this->out(['invitations'=>array_map(function(VaultInvitation $i) use($em): array {
            $c = $em->getRepository(VaultContribution::class)->findOneBy(['invitation'=>$i]);
            return ['id'=>$i->getId(), 'email'=>$i->getRecipientEmail(), 'folder'=>$i->getCompanyFolder(),
                'createdAt'=>$i->getCreatedAt()->format(DATE_ATOM), 'expiresAt'=>$i->getExpiresAt()->format(DATE_ATOM),
                'used'=>!!$i->getRedeemedAt(), 'revoked'=>!!$i->getRevokedAt(),
                'encryptedPrivateKey'=>json_decode($i->getEncryptedPrivateKey(),true),
                'contribution'=>$c ? ['id'=>$c->getId(), 'payload'=>json_decode($c->getCiphertext(),true), 'imported'=>!!$c->getImportedAt()] : null];
        }, $rows)]);
    }
    #[Route('/api/admin/invitations', name: 'ds_admin_invite_create', methods: ['POST'])]
    public function create(Request $r, EntityManagerInterface $em): JsonResponse
    {
        if ($error = $this->writeError($r)) return $error;
        $b = $this->readJsonBody($r, 15000);
        $email=strtolower(trim((string)($b['email'] ?? '')));
        $folder=trim((string)($b['folder'] ?? ''));
        $hours=$b['expiresHours'] ?? null;
        $publicKey=$b['publicKey'] ?? null;
        $private=$b['encryptedPrivateKey'] ?? null;
        if (!filter_var($email,FILTER_VALIDATE_EMAIL) || strlen($email)>180 ||
            strlen($folder)<1 || strlen($folder)>80 || str_contains($folder,'/') || str_contains($folder,'\\') || preg_match('/[\x00-\x1f]/', $folder) || in_array($folder,['.','..'],true) ||
            !in_array($hours,[24,72,168],true) || !is_string($publicKey) || strlen($publicKey)>2000 ||
            !preg_match('/^[A-Za-z0-9+\/=]+$/D',$publicKey) ||
            !is_array($private) || ($private['v'] ?? null)!==1 ||
            !is_string($private['iv'] ?? null) || strlen((string)base64_decode($private['iv'],true))!==12 ||
            !is_string($private['data'] ?? null) || strlen((string)base64_decode($private['data'],true))<32 || strlen($private['data'])>10000) {
            return $this->out(['error'=>'Paramètres d’invitation invalides.'],422);
        }
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $inv = new VaultInvitation(Uuid::v4()->toRfc4122(), $this->user(), hash('sha256',$token), $email, $folder, $publicKey,
            json_encode($private,JSON_THROW_ON_ERROR), (new \DateTimeImmutable('now',new \DateTimeZone('UTC')))->modify('+'.$hours.' hours'));
        $em->persist($inv); $em->flush();
        return $this->out(['ok'=>true, 'id'=>$inv->getId(), 'url'=>$r->getSchemeAndHttpHost().'/contribute/'.$token],201);
    }
    #[Route('/api/admin/invitations/{id}/revoke', name: 'ds_admin_invite_revoke', requirements:['id'=>'[0-9a-fA-F-]{36}'],methods:['POST'])]
    public function revoke(string $id, Request $r, EntityManagerInterface $em): JsonResponse
    {
        if ($error = $this->writeError($r)) return $error;
        $i=$em->getRepository(VaultInvitation::class)->find($id);
        if (!$i) return $this->out(['error'=>'Invitation introuvable.'],404);
        if ($i->getRevokedAt() !== null) return $this->out(['error'=>'Invitation déjà révoquée.'],409);
        $db = $em->getConnection();
        $db->beginTransaction();
        try {
            $i->revoke();
            $em->flush();
            // Ne journaliser que les métadonnées ; jamais les clés de contribution.
            $db->insert('vault_admin_audit', [
                'id'=>Uuid::v4()->toRfc4122(), 'actor_email'=>$this->user()->getEmail(),
                'subject_email'=>$i->getRecipientEmail(), 'action'=>'invitation.revoked',
                'details'=>'{}', 'created_at'=>gmdate('Y-m-d H:i:s'),
            ]);
            $db->commit();
        } catch (\Throwable $e) {
            $db->rollBack();
            return $this->out(['error'=>'Révocation impossible.'],500);
        }
        return $this->out(['ok'=>true]);
    }
    #[Route('/api/admin/contributions/{id}/imported',name:'ds_admin_imported',requirements:['id'=>'[0-9a-fA-F-]{36}'],methods:['POST'])]
    public function imported(string $id, Request $r, EntityManagerInterface $em): JsonResponse
    {
        if ($error = $this->writeError($r)) return $error;
        $c=$em->getRepository(VaultContribution::class)->findOneBy(['id'=>$id]);
        if (!$c) return $this->out(['error'=>'Contribution introuvable.'],404);
        // Ownership validated by invitation lookup, not by knowing a contribution ID.
        // Restriction explicite par l'invitation associee.
        if ($c->getInvitation()->getOwner()->getId() !== $this->user()->getId()) return $this->out(['error'=>'Accès refusé.'],403);
        $c->markImported(); $em->flush(); return $this->out(['ok'=>true]);
    }
}
