<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\SecureSend;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

final class SendController extends AbstractController
{
    private function response(array $data, int $code = 200): JsonResponse
    {
        return (new JsonResponse($data, $code))->setPrivate();
    }

    private function authenticatedUser(): User
    {
        $user = $this->getUser();
        if (!$user instanceof User) {
            throw $this->createAccessDeniedException();
        }
        return $user;
    }

    private function csrf(Request $request): bool
    {
        return $this->isCsrfTokenValid('vault_api', (string) $request->headers->get('X-CSRF-Token', ''));
    }

    private function envelope(mixed $data, int $maxBytes): ?string
    {
        if (!is_array($data) || ($data['v'] ?? null) !== 1 || !is_string($data['iv'] ?? null) || !is_string($data['data'] ?? null)) {
            return null;
        }
        $iv = base64_decode($data['iv'], true);
        $bytes = base64_decode($data['data'], true);
        if ($iv === false || strlen($iv) !== 12 || $bytes === false || strlen($bytes) < 16 || strlen($bytes) > $maxBytes) {
            return null;
        }
        return json_encode(['v'=>1, 'iv'=>$data['iv'], 'data'=>$data['data']], JSON_THROW_ON_ERROR);
    }

    private function body(Request $request, int $max): ?array
    {
        if (strlen($request->getContent()) > $max) {
            return null;
        }
        try {
            $body = json_decode($request->getContent(), true, 8, JSON_THROW_ON_ERROR);
            return is_array($body) ? $body : null;
        } catch (\JsonException) {
            return null;
        }
    }

    #[Route('/api/sends', name: 'send_list', methods: ['GET'])]
    public function list(EntityManagerInterface $em): JsonResponse
    {
        $rows = $em->getRepository(SecureSend::class)->findBy(['owner' => $this->authenticatedUser()], ['createdAt'=>'DESC'], 1000);
        return $this->response(['sends'=>array_map(static fn(SecureSend $s) => [
            'id'=>$s->getId(), 'kind'=>$s->getKind(), 'ownerPayload'=>json_decode($s->getOwnerPayload(), true),
            'expiresAt'=>$s->getExpiresAt()->format(DATE_ATOM), 'createdAt'=>$s->getCreatedAt()->format(DATE_ATOM),
            'views'=>$s->getViews(), 'maxViews'=>$s->getMaxViews(), 'disabled'=>$s->isDisabled(),
        ], $rows)]);
    }

    #[Route('/api/sends', name: 'send_create', methods: ['POST'])]
    public function create(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->response(['error'=>'CSRF invalide.'], 403);
        $body = $this->body($request, 4_500_000);
        if ($body === null) return $this->response(['error'=>'Requête trop grande ou invalide.'], 413);
        $token = $body['token'] ?? null;
        $kind = $body['kind'] ?? null;
        $hours = $body['expireHours'] ?? null;
        $max = $body['maxViews'] ?? null;
        $pass = $body['password'] ?? null;
        $payload = $this->envelope($body['payload'] ?? null, 3_300_000);
        $ownerPayload = $this->envelope($body['ownerPayload'] ?? null, 32_000);
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $token) ||
            !in_array($kind, ['text','file'], true) || !in_array($hours, [1,24,168,720], true) ||
            ($max !== null && (!is_int($max) || $max < 1 || $max > 1000)) ||
            ($pass !== null && (!is_string($pass) || strlen($pass) < 8 || strlen($pass) > 72)) ||
            $payload === null || $ownerPayload === null) {
            return $this->response(['error'=>'Paramètres du Send invalides.'], 422);
        }
        $expires = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $send = new SecureSend(Uuid::v4()->toRfc4122(), $this->authenticatedUser(), hash('sha256', $token), $kind,
            $payload, $ownerPayload, $pass ? password_hash($pass, PASSWORD_DEFAULT) : null,
            $expires->modify('+' . $hours . ' hours'), $max);
        $em->persist($send);
        try { $em->flush(); } catch (\Doctrine\DBAL\Exception\UniqueConstraintViolationException) {
            return $this->response(['error'=>'Collision de jeton. Réessayez.'], 409);
        }
        return $this->response(['id'=>$send->getId(), 'ok'=>true], 201);
    }

    #[Route('/api/sends/{id}', name: 'send_update', requirements:['id'=>'[0-9a-fA-F-]{36}'], methods:['PATCH'])]
    public function toggle(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->response(['error'=>'CSRF invalide.'], 403);
        $send = $em->getRepository(SecureSend::class)->findOneBy(['id'=>$id, 'owner'=>$this->authenticatedUser()]);
        if (!$send) return $this->response(['error'=>'Introuvable.'], 404);
        $body = $this->body($request, 1000);
        if (!is_bool($body['disabled'] ?? null)) return $this->response(['error'=>'Option invalide.'], 422);
        $send->setDisabled($body['disabled']);
        $em->flush();
        return $this->response(['ok'=>true]);
    }

    #[Route('/api/sends/{id}', name: 'send_delete', requirements:['id'=>'[0-9a-fA-F-]{36}'], methods:['DELETE'])]
    public function delete(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->response(['error'=>'CSRF invalide.'], 403);
        $send = $em->getRepository(SecureSend::class)->findOneBy(['id'=>$id, 'owner'=>$this->authenticatedUser()]);
        if (!$send) return $this->response(['error'=>'Introuvable.'], 404);
        $em->remove($send);
        $em->flush();
        return $this->response(['ok'=>true]);
    }

    #[Route('/s/{token}', name: 'send_public_page', requirements:['token'=>'[A-Za-z0-9_-]{43}'], methods:['GET'])]
    public function publicPage(): Response
    {
        return $this->render('send/view.html.twig');
    }

    #[Route('/api/send-public/{token}/open', name: 'send_public_open', requirements:['token'=>'[A-Za-z0-9_-]{43}'], methods:['POST'])]
    public function open(string $token, Request $request, EntityManagerInterface $em, RateLimiterFactory $sendOpenLimiter): JsonResponse
    {
        // Rate limiting per client and share token to protect the optional access password.
        $identifier = hash('sha256', $token . '|' . ($request->getClientIp() ?? 'unknown'));
        if (!$sendOpenLimiter->create($identifier)->consume(1)->isAccepted()) {
            return $this->response(['error'=>'Trop de tentatives. Réessayez plus tard.'], 429);
        }
        $body = $this->body($request, 500);
        if ($body === null) return $this->response(['error'=>'Requête invalide.'], 400);
        // Direct conditional update, avoiding concurrent access-count bypass.
        $row = $em->getConnection()->fetchAssociative(
            'SELECT id, password_hash FROM secure_send WHERE token_hash = :hash AND disabled = :disabled AND expires_at > :now AND (max_views IS NULL OR views < max_views)',
            ['hash'=>hash('sha256', $token), 'disabled'=>false, 'now'=>(new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s')],
            ['disabled'=>\Doctrine\DBAL\ParameterType::BOOLEAN]
        );
        if (!$row) return $this->response(['error'=>'Ce partage a expiré ou est indisponible.'], 404);
        $password = $body['password'] ?? '';
        if (!is_string($password) || strlen($password) > 256) {
            return $this->response(['error'=>'Parametre invalide.'], 422);
        }
        if ($row['password_hash'] !== null && !password_verify($password, $row['password_hash'])) {
            return $this->response(['error'=>'Mot de passe d’accès incorrect.'], 403);
        }
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        $changed = $em->getConnection()->executeStatement(
            'UPDATE secure_send SET views = views + 1 WHERE id = :id AND disabled = :disabled AND expires_at > :now AND (max_views IS NULL OR views < max_views)',
            ['id'=>$row['id'], 'disabled'=>false, 'now'=>$now],
            ['disabled'=>\Doctrine\DBAL\ParameterType::BOOLEAN]
        );
        if ($changed !== 1) return $this->response(['error'=>'Ce partage est indisponible.'], 404);
        $payload = $em->getConnection()->fetchOne('SELECT payload FROM secure_send WHERE id = :id', ['id'=>$row['id']]);
        return $this->response(['payload'=>json_decode($payload, true)]);
    }
}
