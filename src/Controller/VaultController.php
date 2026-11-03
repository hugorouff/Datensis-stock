<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class VaultController extends AbstractController
{
    public function __construct(
        #[\Symfony\Component\DependencyInjection\Attribute\Autowire('%app.vault_2fa_enabled%')] private readonly bool $twoFactorEnabled,
    ) {}

    #[Route('/', name: 'app_home', methods: ['GET'])]
    public function home(): Response
    {
        return $this->redirectToRoute($this->isGranted('ROLE_ADMIN') ? 'app_admin' : 'app_vault');
    }

    #[Route('/admin', name: 'app_admin', methods: ['GET'])]
    public function admin(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');
        $response = $this->render('admin/index.html.twig');
        $response->headers->set('Cache-Control', 'private, no-store, max-age=0');
        return $response;
    }

    #[Route('/vault', name: 'app_vault', methods: ['GET'])]
    #[Route('/passwords', name: 'app_passwords', methods: ['GET'])]
    #[Route('/shares', name: 'app_shares_page', methods: ['GET'])]
    #[Route('/send', name: 'app_send', methods: ['GET'])]
    #[Route('/security-center', name: 'app_security_center', methods: ['GET'])]
    #[Route('/generator', name: 'app_generator', methods: ['GET'])]
    #[Route('/transfer', name: 'app_transfer', methods: ['GET'])]
    #[Route('/settings', name: 'app_vault_settings', methods: ['GET'])]
    #[Route('/cockpit', name: 'app_cockpit', methods: ['GET'])]
    #[Route('/actions', name: 'app_actions', methods: ['GET'])]
    #[Route('/mini', name: 'app_mini', methods: ['GET'])]
    public function index(): Response
    {
        if ($this->isGranted('ROLE_ADMIN')) {
            return $this->redirectToRoute('app_admin');
        }
        return $this->render('vault/index.html.twig', [
            'vault_2fa_enabled' => $this->twoFactorEnabled,
        ]);
    }
}
