<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Uid\Uuid;

final class AuthController extends AbstractController
{
    // Permet de changer de compte depuis un onglet de connexion conserve par Edge,
    // sans utiliser une fenetre privee. Ne fournit aucun secret.
    #[Route('/auth/session', name: 'app_auth_session', methods: ['GET'])]
    public function sessionState(CsrfTokenManagerInterface $csrf): JsonResponse
    {
        $user = $this->getUser();
        return new JsonResponse([
            'authenticated' => $user instanceof User,
            'logoutCsrf' => $user instanceof User ? $csrf->getToken('logout')->getValue() : null,
        ], 200, ['Cache-Control' => 'no-store, private']);
    }

    #[Route('/login', name: 'app_login', methods: ['GET', 'POST'])]
    public function login(
        AuthenticationUtils $authenticationUtils,
        bool $allowRegistration,
        #[\Symfony\Component\DependencyInjection\Attribute\Autowire('%app.vault_2fa_enabled%')] bool $twoFactorEnabled,
    ): Response
    {
        if ($this->getUser() !== null) {
            // An already authenticated session is NOT equivalent to verified 2FA.
            return $this->redirectToRoute($twoFactorEnabled ? 'app_twofactor_challenge' : ($this->isGranted('ROLE_ADMIN') ? 'app_admin' : 'app_vault'));
        }

        return $this->render('auth/login.html.twig', [
            'last_username' => $authenticationUtils->getLastUsername(),
            'error' => $authenticationUtils->getLastAuthenticationError(),
            'allow_registration' => $allowRegistration,
            'vault_2fa_enabled' => $twoFactorEnabled,
        ]);
    }

    #[Route('/register', name: 'app_register', methods: ['GET', 'POST'])]
    public function register(
        Request $request,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $passwordHasher,
        bool $allowRegistration,
        #[\Symfony\Component\DependencyInjection\Attribute\Autowire('%app.vault_2fa_enabled%')] bool $twoFactorEnabled,
    ): Response {
        if (!$allowRegistration) {
            throw $this->createNotFoundException('Inscriptions desactivees.');
        }
        if ($this->getUser() !== null) {
            // An already authenticated session is NOT equivalent to verified 2FA.
            return $this->redirectToRoute($twoFactorEnabled ? 'app_twofactor_challenge' : ($this->isGranted('ROLE_ADMIN') ? 'app_admin' : 'app_vault'));
        }

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('register', (string) $request->request->get('_csrf_token', ''))) {
                throw $this->createAccessDeniedException('CSRF invalide.');
            }
            $email = strtolower(trim((string) $request->request->get('email', '')));
            $password = (string) $request->request->get('password', '');
            $confirm = (string) $request->request->get('confirm', '');
            if (strlen($email) > 180 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
                $this->addFlash('error', 'Adresse e-mail invalide.');
            } elseif (strlen($password) < 12 || strlen($password) > 1024) {
                $this->addFlash('error', 'Choisissez un mot de passe de connexion entre 12 et 1024 caracteres.');
            } elseif (!hash_equals($password, $confirm)) {
                $this->addFlash('error', 'Les deux mots de passe ne correspondent pas.');
            } elseif ($em->getRepository(User::class)->findOneBy(['email' => $email])) {
                $this->addFlash('error', 'Adresse deja utilisee.');
            } else {
                $user = new User(Uuid::v4()->toRfc4122(), $email);
                $user->setPasswordHash($passwordHasher->hashPassword($user, $password));
                $em->persist($user);
                $em->flush();
                $this->addFlash('success', 'Compte créé. Connectez-vous avec votre mot de passe principal pour initialiser le coffre.');
                return $this->redirectToRoute('app_login');
            }
        }

        return $this->render('auth/register.html.twig');
    }

    #[Route('/logout', name: 'app_logout', methods: ['POST'])]
    public function logout(): never
    {
        throw new \LogicException('Intercepte par le pare-feu de Symfony.');
    }
}
