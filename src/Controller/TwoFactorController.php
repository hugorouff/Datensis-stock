<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Security\EmailOtpCode;
use App\Security\EmailOtpSender;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;

/** Double facteur obligatoire par e-mail via Brevo. Aucune suppression des secrets TOTP historiques. */
final class TwoFactorController extends AbstractController
{
    private const POLICY = 'brevo-email-v1';

    public function __construct(
        #[Autowire('%app.vault_2fa_enabled%')] private readonly bool $enabled,
    ) {}

    #[Route('/2fa', name: 'app_twofactor_challenge', methods: ['GET'])]
    public function challenge(Request $request): Response
    {
        $user = $this->getUser();
        if (!$this->enabled) return $this->redirectToRoute('app_home');
        if (!$user instanceof User) return $this->redirectToRoute('app_login');
        if ($request->getSession()->get('vault_2fa_ok') === $user->getId()
            && $request->getSession()->get('vault_2fa_policy') === self::POLICY) {
            return $this->redirectToRoute('app_home');
        }
        return $this->render('auth/two_factor.html.twig', ['email' => $user->getEmail()]);
    }

    #[Route('/2fa/send', name: 'app_twofactor_send', methods: ['POST'])]
    public function send(
        Request $request,
        EmailOtpSender $sender,
        #[Autowire(service: 'limiter.vault_email_otp_send')] RateLimiterFactory $sendLimiter,
    ): JsonResponse {
        if (!$this->enabled) return $this->json(['error' => '2FA desactivee.'], 403);
        if (!$this->isCsrfTokenValid('2fa', (string) $request->headers->get('X-CSRF-Token', ''))) {
            return $this->json(['error' => 'CSRF invalide.'], 403);
        }
        $user = $this->getUser();
        if (!$user instanceof User) return $this->json(['error' => 'Connexion requise.'], 401);
        $session = $request->getSession();
        $now = time();
        $pending = $session->get('otp_mail_pending');
        if (is_array($pending) && ($pending['user'] ?? null) === $user->getId()
            && ($pending['expires'] ?? 0) >= $now && $now - (int) ($pending['sentAt'] ?? 0) < 60) {
            return $this->json(['ok' => true, 'alreadySent' => true, 'message' => 'Un code a deja ete envoye. Patientez avant un renvoi.']);
        }
        $limit = $sendLimiter->create($user->getId())->consume(1);
        if (!$limit->isAccepted()) {
            return $this->json(['error' => 'Trop de demandes de code. Reessayez dans 15 minutes.'], 429);
        }
        $issued = EmailOtpCode::issue($user->getId(), $now);
        try {
            $sender->send($user->getEmail(), $issued['code']);
        } catch (\RuntimeException $e) {
            // Ne pas exposer de details d'API Brevo ni de secrets dans la reponse.
            if (str_starts_with($e->getMessage(), 'Brevo non configure.')) {
                return $this->json(['error' => 'Brevo non configure : renseignez la cle API et une adresse expediteur verifiee.'], 503);
            }
            return $this->json(['error' => 'Envoi du code impossible. Verifiez Brevo et reessayez.'], 503);
        } catch (\Throwable) {
            return $this->json(['error' => 'Envoi du code impossible. Verifiez Brevo et reessayez.'], 503);
        }
        $session->set('otp_mail_pending', $issued['challenge']);
        return $this->json(['ok' => true, 'message' => 'Un code de verification a ete envoye a votre adresse.']);
    }

    #[Route('/2fa/verify', name: 'app_twofactor_verify', methods: ['POST'])]
    public function verify(
        Request $request,
        #[Autowire(service: 'limiter.vault_email_otp_verify')] RateLimiterFactory $verifyLimiter,
    ): JsonResponse {
        if (!$this->enabled) return $this->json(['error' => '2FA desactivee.'], 403);
        if (!$this->isCsrfTokenValid('2fa', (string) $request->headers->get('X-CSRF-Token', ''))) {
            return $this->json(['error' => 'CSRF invalide.'], 403);
        }
        $user = $this->getUser();
        if (!$user instanceof User) return $this->json(['error' => 'Connexion requise.'], 401);
        $session = $request->getSession();
        $pending = $session->get('otp_mail_pending');
        if (!is_array($pending) || ($pending['user'] ?? null) !== $user->getId() || ($pending['expires'] ?? 0) < time()) {
            $session->remove('otp_mail_pending');
            return $this->json(['error' => 'Code absent ou expire. Demandez un nouveau code.'], 403);
        }
        if ((int) ($pending['attempts'] ?? 0) >= 5) {
            $session->remove('otp_mail_pending');
            return $this->json(['error' => 'Trop de tentatives. Demandez un nouveau code apres le delai.'], 429);
        }
        $body = json_decode($request->getContent(), true);
        $code = trim((string) (is_array($body) ? ($body['code'] ?? '') : ''));
        if (!EmailOtpCode::matches($pending, $user->getId(), $code, time())) {
            $pending['attempts'] = (int) ($pending['attempts'] ?? 0) + 1;
            $session->set('otp_mail_pending', $pending);
            $limit = $verifyLimiter->create($user->getId())->consume(1);
            if (!$limit->isAccepted()) {
                return $this->json(['error' => 'Trop de codes essayes. Reessayez dans 15 minutes.'], 429);
            }
            return $this->json(['error' => 'Code invalide.'], 403);
        }
        $session->remove('otp_mail_pending');
        $session->set('vault_2fa_ok', $user->getId());
        $session->set('vault_2fa_policy', self::POLICY);
        return $this->json(['ok' => true]);
    }

    #[Route('/2fa/lock', name: 'app_twofactor_lock', methods: ['POST'])]
    public function lock(Request $request): JsonResponse
    {
        if (!$this->enabled) return $this->json(['error' => '2FA desactivee.'], 403);
        $token = (string) ($request->headers->get('X-CSRF-Token') ?? $request->request->get('_csrf_token', ''));
        if (!$this->isCsrfTokenValid('2fa', $token)) return $this->json(['error' => 'CSRF invalide.'], 403);
        $session = $request->getSession();
        $session->remove('vault_2fa_ok');
        $session->remove('vault_2fa_policy');
        $session->remove('otp_mail_pending');
        return $this->json(['ok' => true]);
    }
}
