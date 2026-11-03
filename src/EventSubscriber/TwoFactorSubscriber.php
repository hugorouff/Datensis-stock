<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Entity\User;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

final class TwoFactorSubscriber
{
    public function __construct(
        private readonly Security $security,
        #[Autowire('%app.vault_2fa_enabled%')] private readonly bool $enabled,
    ) {}

    #[AsEventListener(event: LoginSuccessEvent::class)]
    public function onLogin(LoginSuccessEvent $event): void
    {
        if (!$this->enabled || !$event->getUser() instanceof User) return;
        $session = $event->getRequest()->getSession();
        foreach (['vault_2fa_ok', 'vault_2fa_policy', 'otp_mail_pending', 'otp_errors', 'otp_since', 'otp_pending'] as $key) {
            $session->remove($key);
        }
        $event->setResponse(new RedirectResponse('/2fa'));
    }

    #[AsEventListener(event: KernelEvents::REQUEST, priority: -12)]
    public function protect(RequestEvent $event): void
    {
        if (!$this->enabled || !$event->isMainRequest()) return;
        $request = $event->getRequest();
        $path = $request->getPathInfo();
        if (preg_match('#^/(?:assets/|icons/|login$|register$|s/|api/send-public/|manifest\.webmanifest$|sw\.js$)#', $path)) return;
        if (in_array($path, ['/2fa', '/2fa/send', '/2fa/verify', '/2fa/lock', '/logout', '/auth/session'], true)) return;
        $user = $this->security->getUser();
        if (!$user instanceof User) return;
        if ($request->getSession()->get('vault_2fa_ok') === $user->getId()
            && $request->getSession()->get('vault_2fa_policy') === 'brevo-email-v1') return;
        $event->setResponse(str_starts_with($path, '/api/')
            ? new JsonResponse(['error' => 'Verification par e-mail obligatoire.'], 403, ['Cache-Control' => 'no-store'])
            : new RedirectResponse('/2fa', 302, ['Cache-Control' => 'no-store']));
    }
}
