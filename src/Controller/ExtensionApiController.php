<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Entity\SecureSend;
use App\Entity\VaultEntry;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\DependencyInjection\Attribute\Target;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

/** API exclusivement pour le popup de l'extension.
 * Aucun cookie de session, aucune donnee en clair et aucun jeton persistant dans le navigateur.
 * Les jetons opaques expires sont haches en base et doivent etre presentes via Authorization.
 */
#[Route('/api/extension')]
final class ExtensionApiController extends AbstractController
{
    public function __construct(
        #[Autowire('%app.vault_2fa_enabled%')] private readonly bool $twoFactorEnabled,
    ) {}

    private function respond(array $value, int $status = 200): JsonResponse
    {
        return new JsonResponse($value, $status, [
            'Cache-Control' => 'no-store, private',
            'Pragma' => 'no-cache',
        ]);
    }

    private function input(Request $request): ?array
    {
        if (strlen($request->getContent()) > 40000) return null;
        try {
            $input = json_decode($request->getContent(), true, 12, JSON_THROW_ON_ERROR);
            return is_array($input) ? $input : null;
        } catch (\JsonException) {
            return null;
        }
    }

    private function envelope(mixed $payload): ?string
    {
        if (!is_array($payload) || ($payload['v'] ?? null) !== 1 ||
            !is_string($payload['iv'] ?? null) || !is_string($payload['data'] ?? null)) return null;
        $iv = base64_decode($payload['iv'], true);
        $ciphertext = base64_decode($payload['data'], true);
        if ($iv === false || strlen($iv) !== 12 || $ciphertext === false ||
            strlen($ciphertext) < 16 || strlen($ciphertext) > 30000) return null;
        return json_encode(['v' => 1, 'iv' => $payload['iv'], 'data' => $payload['data']], JSON_THROW_ON_ERROR);
    }

    private function account(Request $request, EntityManagerInterface $em): ?User
    {
        if ($this->twoFactorEnabled) return null; // Bloquer toute API si la 2FA est reactivee avant d'implementer son challenge pour l'extension.
        $header = (string) $request->headers->get('Authorization', '');
        if (!preg_match('/^Bearer ([A-Za-z0-9_-]{43})$/D', $header, $match)) return null;
        $tokenHash = hash('sha256', $match[1]);
        $userId = $em->getConnection()->fetchOne(
            'SELECT owner_id FROM vault_extension_session WHERE token_hash = :hash AND expires_at > :now',
            ['hash' => $tokenHash, 'now' => time()]
        );
        $user = is_string($userId) ? $em->getRepository(User::class)->find($userId) : null;
        if (!$user || $user->isDisabled() || $user->needsPasswordChange() || in_array('ROLE_ADMIN', $user->getRoles(), true)) return null;
        return $user;
    }

    private function entries(EntityManagerInterface $em, User $user): array
    {
        return array_map(static fn (VaultEntry $entry): array => [
            'id' => $entry->getId(),
            'payload' => json_decode($entry->getEncryptedPayload(), true),
            'updatedAt' => $entry->getUpdatedAt()->format(DATE_ATOM),
        ], $em->getRepository(VaultEntry::class)->findBy(['owner' => $user], ['updatedAt' => 'DESC'], 3000));
    }

    private function stateData(EntityManagerInterface $em, User $user): array
    {
        return [
            'initialized' => $user->getVaultSalt() !== null && $user->getVaultCheck() !== null,
            'salt' => $user->getVaultSalt(),
            'check' => $user->getVaultCheck() ? json_decode($user->getVaultCheck(), true) : null,
            'kdfVersion' => $user->getVaultKdfVersion(),
            'entries' => $this->entries($em, $user),
        ];
    }

    #[Route('/session', name: 'app_ext_session', methods: ['POST'])]
    public function login(
        Request $request,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $hasher,
        #[Target('vault_extension_login')] RateLimiterFactoryInterface $loginLimiter,
    ): JsonResponse {
        if ($this->twoFactorEnabled) return $this->respond(['error' => '2FA activee : connexion par extension indisponible jusqu a prise en charge du challenge.'], 423);
        $host = $request->getHost();
        if (!$request->isSecure() && !in_array($host, ['localhost', '127.0.0.1'], true)) {
            return $this->respond(['error' => 'HTTPS obligatoire.'], 403);
        }
        $input = $this->input($request);
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $password = $input['password'] ?? null;
        if (strlen($email) > 180 || !is_string($password) || strlen($password) > 1024 || strlen($password) === 0) {
            return $this->respond(['error' => 'Identifiants incorrects.'], 401);
        }
        $ip = (string) $request->getClientIp();
        $identity = hash('sha256', $ip . '|' . $email);
        $limiter = $loginLimiter->create($identity);
        $attempt = $limiter->consume(1);
        if (!$attempt->isAccepted()) {
            $seconds = max(1, $attempt->getRetryAfter()->getTimestamp() - time());
            $response = $this->respond([
                'error' => 'Trop de tentatives de connexion. Réessayez après le délai indiqué.',
                'retryAfter' => $seconds,
            ], 429);
            $response->headers->set('Retry-After', (string) $seconds);
            return $response;
        }
        $user = $em->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user instanceof User || $user->isDisabled() || !$hasher->isPasswordValid($user, $password)) {
            return $this->respond(['error' => 'Identifiants incorrects.'], 401);
        }
        if ($hasher->needsRehash($user)) {
            $user->setPasswordHash($hasher->hashPassword($user, $password));
            $em->flush();
        }
        if ($user->needsPasswordChange()) return $this->respond(['error' => 'Choisissez votre mot de passe personnel sur le site avant d’utiliser l’extension.'], 403);
        if (in_array('ROLE_ADMIN', $user->getRoles(), true)) return $this->respond(['error' => 'Un compte administrateur utilise exclusivement /admin.'], 403);
        // Le site utilise la session Symfony ; le panneau utilise une table de sessions
        // distincte. Le schema doit etre reellement present, meme si Doctrine indique
        // que la migration est deja executee.
        $conn = $em->getConnection();
        if (!$conn->createSchemaManager()->tablesExist(['vault_extension_session'])) {
            return $this->respond([
                'error' => 'La table des sessions de l’extension est absente. Exécutez php bin/console app:extension:doctor --repair.',
                'code' => 'EXTENSION_SCHEMA_MISSING',
            ], 503);
        }

        // Lire le coffre avant de delivrer un jeton : si une requete echoue,
        // aucune session orpheline n'est creee.
        $vaultState = $this->stateData($em, $user);
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $expires = time() + 600;
        $conn->transactional(static function ($transaction) use ($token, $expires, $user): void {
            $transaction->executeStatement('DELETE FROM vault_extension_session WHERE expires_at <= :now', ['now' => time()]);
            $transaction->insert('vault_extension_session', [
                'id' => Uuid::v4()->toRfc4122(),
                'owner_id' => $user->getId(),
                'token_hash' => hash('sha256', $token),
                'expires_at' => $expires,
            ]);
        });
        // Une connexion reussie ne doit pas maintenir le compteur de tentatives sature.
        $limiter->reset();
        return $this->respond(['token' => $token, 'expiresAt' => $expires, 'state' => $vaultState]);
    }

    #[Route('/state', name: 'app_ext_state', methods: ['GET'])]
    public function state(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        return $user ? $this->respond($this->stateData($em, $user)) : $this->respond(['error' => 'Session extension invalide ou expiree.'], 401);
    }

    #[Route('/initialize', name: 'app_ext_initialize', methods: ['POST'])]
    public function initialize(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        $body = $this->input($request);
        $salt = $body['salt'] ?? null;
        $check = $this->envelope($body['check'] ?? null);
        $kdfVersion = $body['kdfVersion'] ?? 1;
        if (!is_string($salt) || strlen($salt) > 64 || strlen((string) base64_decode($salt, true)) !== 16 ||
            $check === null || !in_array($kdfVersion, [1, 2], true)) {
            return $this->respond(['error' => 'Initialisation invalide.'], 422);
        }
        $changed = $em->getConnection()->executeStatement(
            'UPDATE vault_user SET vault_salt = :salt, vault_check = :check, vault_kdf_version = :kdfVersion WHERE id = :id AND vault_salt IS NULL AND vault_check IS NULL',
            ['salt' => $salt, 'check' => $check, 'kdfVersion' => $kdfVersion, 'id' => $user->getId()]
        );
        return $changed === 1 ? $this->respond(['ok' => true], 201) : $this->respond(['error' => 'Coffre deja initialise.'], 409);
    }

    #[Route('/entries', name: 'app_ext_create', methods: ['POST'])]
    public function create(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        if (!$user->getVaultSalt()) return $this->respond(['error' => 'Initialisez le coffre.'], 409);
        $body = $this->input($request);
        $ciphertext = $this->envelope($body['payload'] ?? null);
        if ($ciphertext === null) return $this->respond(['error' => 'Donnees chiffrees invalides.'], 422);
        $entry = new VaultEntry(Uuid::v4()->toRfc4122(), $user, $ciphertext);
        $em->persist($entry);
        $em->flush();
        return $this->respond(['id' => $entry->getId(), 'updatedAt' => $entry->getUpdatedAt()->format(DATE_ATOM)], 201);
    }

    #[Route('/entries/{id}', name: 'app_ext_update', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['PUT'])]
    public function update(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        $entry = $em->getRepository(VaultEntry::class)->findOneBy(['id' => $id, 'owner' => $user]);
        if (!$entry) return $this->respond(['error' => 'Element introuvable.'], 404);
        $body = $this->input($request);
        $ciphertext = $this->envelope($body['payload'] ?? null);
        if ($ciphertext === null) return $this->respond(['error' => 'Donnees chiffrees invalides.'], 422);
        $entry->replacePayload($ciphertext);
        $em->flush();
        return $this->respond(['ok' => true, 'updatedAt' => $entry->getUpdatedAt()->format(DATE_ATOM)]);
    }

    #[Route('/entries/{id}', name: 'app_ext_delete', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['DELETE'])]
    public function delete(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        $entry = $em->getRepository(VaultEntry::class)->findOneBy(['id' => $id, 'owner' => $user]);
        if (!$entry) return $this->respond(['error' => 'Element introuvable.'], 404);
        $em->remove($entry);
        $em->flush();
        return $this->respond(['ok' => true]);
    }

    #[Route('/sends', name: 'app_ext_sends', methods: ['GET'])]
    public function sends(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        $sends = $em->getRepository(SecureSend::class)->findBy(['owner' => $user], ['createdAt' => 'DESC'], 1000);
        return $this->respond(['sends' => array_map(static fn (SecureSend $s) => [
            'id' => $s->getId(), 'kind' => $s->getKind(),
            'ownerPayload' => json_decode($s->getOwnerPayload(), true),
            'expiresAt' => $s->getExpiresAt()->format(DATE_ATOM),
            'views' => $s->getViews(), 'maxViews' => $s->getMaxViews(),
            'disabled' => $s->isDisabled(),
        ], $sends)]);
    }

    #[Route('/sends', name: 'app_ext_send_create', methods: ['POST'])]
    public function createSend(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        $body = $this->input($request);
        $token = $body['token'] ?? null;
        $hours = $body['expireHours'] ?? null;
        $max = $body['maxViews'] ?? null;
        $password = $body['password'] ?? null;
        $payload = $this->envelope($body['payload'] ?? null);
        $ownerPayload = $this->envelope($body['ownerPayload'] ?? null);
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $token) ||
            !in_array($hours, [1,24,168,720], true) ||
            ($max !== null && (!is_int($max) || $max < 1 || $max > 1000)) ||
            ($password !== null && (!is_string($password) || strlen($password) < 8 || strlen($password) > 72)) ||
            $payload === null || $ownerPayload === null) {
            return $this->respond(['error' => 'Send invalide.'], 422);
        }
        $send = new SecureSend(
            Uuid::v4()->toRfc4122(), $user, hash('sha256', $token), 'text',
            $payload, $ownerPayload, $password ? password_hash($password, PASSWORD_DEFAULT) : null,
            (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify('+' . $hours . ' hours'), $max
        );
        $em->persist($send);
        $em->flush();
        return $this->respond(['id' => $send->getId()], 201);
    }

    #[Route('/sends/{id}', name: 'app_ext_send_toggle', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['PATCH'])]
    public function toggleSend(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        $send = $em->getRepository(SecureSend::class)->findOneBy(['id' => $id, 'owner' => $user]);
        if (!$send) return $this->respond(['error' => 'Send introuvable.'], 404);
        $body = $this->input($request);
        if (!is_bool($body['disabled'] ?? null)) return $this->respond(['error' => 'Option invalide.'], 422);
        $send->setDisabled($body['disabled']);
        $em->flush();
        return $this->respond(['ok' => true]);
    }

    #[Route('/sends/{id}', name: 'app_ext_send_delete', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['DELETE'])]
    public function deleteSend(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        $user = $this->account($request, $em);
        if (!$user) return $this->respond(['error' => 'Session expiree.'], 401);
        $send = $em->getRepository(SecureSend::class)->findOneBy(['id' => $id, 'owner' => $user]);
        if (!$send) return $this->respond(['error' => 'Send introuvable.'], 404);
        $em->remove($send);
        $em->flush();
        return $this->respond(['ok' => true]);
    }

    #[Route('/logout', name: 'app_ext_logout', methods: ['POST'])]
    public function logout(Request $request, EntityManagerInterface $em): JsonResponse
    {
        $header = (string) $request->headers->get('Authorization', '');
        if (preg_match('/^Bearer ([A-Za-z0-9_-]{43})$/D', $header, $parts)) {
            $em->getConnection()->executeStatement('DELETE FROM vault_extension_session WHERE token_hash = :hash', ['hash' => hash('sha256', $parts[1])]);
        }
        return $this->respond(['ok' => true]);
    }
}
