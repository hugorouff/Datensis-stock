<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

final class FirstLoginController extends AbstractController
{
    #[Route('/account/activate', name: 'ds_account_activate', methods: ['GET', 'POST'])]
    public function activate(Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $hasher, TokenStorageInterface $tokens): Response
    {
        $user = $this->getUser();
        if (!$user instanceof User || $user->isDisabled()) return $this->redirectToRoute('app_login');
        if (!$user->needsPasswordChange()) return $this->redirectToRoute(in_array('ROLE_ADMIN', $user->getRoles(), true) ? 'app_admin' : 'app_vault');
        $message = null;
        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('first_login', (string) $request->request->get('_csrf_token', ''))) {
                throw $this->createAccessDeniedException('CSRF invalide.');
            }
            $current = (string) $request->request->get('current', '');
            $new = (string) $request->request->get('new', '');
            $confirm = (string) $request->request->get('confirm', '');
            if (!$hasher->isPasswordValid($user, $current)) $message = 'Mot de passe temporaire incorrect.';
            elseif (strlen($new) < 16 || strlen($new) > 1024) $message = 'Choisissez un mot de passe d’au moins 16 caractères.';
            elseif (!hash_equals($new, $confirm)) $message = 'Les mots de passe ne correspondent pas.';
            elseif (hash_equals($new, $current)) $message = 'Choisissez un nouveau mot de passe différent du provisoire.';
            elseif ($user->getVaultSalt() !== null || $user->getVaultCheck() !== null || $user->getSharingPrivateKey() !== null || $user->getSharingPublicKey() !== null) {
                $message = 'Ce compte possède déjà des données chiffrées : modification automatique interdite.';
            } else {
                $user->setPasswordHash($hasher->hashPassword($user, $new));
                $user->finishPasswordChange();
                $em->getConnection()->executeStatement('DELETE FROM vault_extension_session WHERE owner_id=:id', ['id'=>$user->getId()]);
                $em->flush();
                $tokens->setToken(null);
                $request->getSession()->invalidate();
                $this->addFlash('success', 'Mot de passe personnel enregistré. Connectez-vous avec votre nouveau mot de passe.');
                return $this->redirectToRoute('app_login');
            }
        }
        return $this->render('auth/activate.html.twig', ['message' => $message, 'email' => $user->getEmail()]);
    }
}
