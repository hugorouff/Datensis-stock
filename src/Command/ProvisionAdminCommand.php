<?php

declare(strict_types=1);

namespace App\Command;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:admin:provision', description: 'Accorder le role ROLE_ADMIN a un compte existant.')]
final class ProvisionAdminCommand extends Command
{
    public function __construct(private readonly EntityManagerInterface $em) { parent::__construct(); }
    protected function configure(): void { $this->addArgument('email', InputArgument::REQUIRED, 'Adresse du compte existant'); }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        if (!$input->isInteractive()) {
            $io->error('Mode interactif requis pour confirmer la promotion.');
            return Command::FAILURE;
        }
        $email = strtolower(trim((string) $input->getArgument('email')));
        $user = $this->em->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            $io->error('Compte introuvable. Pour creer un nouvel administrateur, utilisez app:admin:create.');
            return Command::FAILURE;
        }
        if (!$io->confirm(sprintf('Accorder ROLE_ADMIN au compte existant %s ?', $email), false)) {
            $io->warning('Operation annulee.');
            return Command::FAILURE;
        }
        $user->grantAdmin();
        $this->em->flush();
        $io->success('Role administrateur accorde. Une nouvelle connexion redirigera vers /admin.');
        return Command::SUCCESS;
    }
}
