<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

final class AccountPolicySubscriber
{
    public function __construct(
        private readonly Security $security,
        private readonly EntityManagerInterface $em,
        private readonly TokenStorageInterface $tokens,
        #[Autowire('%app.vault_2fa_enabled%')] private readonly bool $twoFactorEnabled,
    ) {}

    #[AsEventListener(event: LoginSuccessEvent::class)]
    public function onLogin(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        if (!$user instanceof User) return;
        $user->markLastLogin();
        $this->em->flush();
        if ($user->needsPasswordChange() && !$this->twoFactorEnabled) {
            $event->setResponse(new RedirectResponse('/account/activate'));
        }
    }

    #[AsEventListener(event: KernelEvents::REQUEST, priority: -13)]
    public function enforce(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) return;
        $request = $event->getRequest();
        $path = $request->getPathInfo();
        if (preg_match('#^/(?:assets/|icons/|api/extension/|s/|contribute/|api/send-public/)#', $path)) return;
        if (in_array($path, ['/login', '/register', '/logout', '/auth/session', '/2fa', '/2fa/send', '/2fa/verify', '/2fa/lock', '/account/activate'], true)) return;
        $user = $this->security->getUser();
        if (!$user instanceof User) return;
        $row = $this->em->getConnection()->fetchAssociative('SELECT disabled_at, must_change_password, roles FROM vault_user WHERE id=:id', ['id'=>$user->getId()]);
        $roles = $row ? json_decode((string) $row['roles'], true) : null;
        $wasAdmin = in_array('ROLE_ADMIN', $user->getRoles(), true);
        $isAdmin = is_array($roles) && in_array('ROLE_ADMIN', $roles, true);
        // For role changes, invalidate sessions instead of permitting stale elevated tokens.
        if (!$row || $row['disabled_at'] !== null || $wasAdmin !== $isAdmin) {
            $this->tokens->setToken(null);
            if ($request->hasPreviousSession()) $request->getSession()->invalidate();
            $event->setResponse(str_starts_with($path, '/api/')
                ? new JsonResponse(['error'=>'Session expirée ou compte désactivé.'],403,['Cache-Control'=>'no-store'])
                : new RedirectResponse('/login',302,['Cache-Control'=>'no-store']));
            return;
        }
        if ((bool) $row['must_change_password']) {
            $event->setResponse(str_starts_with($path, '/api/')
                ? new JsonResponse(['error'=>'Vous devez choisir votre propre mot de passe avant d’utiliser ce compte.'],403,['Cache-Control'=>'no-store'])
                : new RedirectResponse('/account/activate',302,['Cache-Control'=>'no-store']));
        }
    }
}
