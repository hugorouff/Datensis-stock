<?php

declare(strict_types=1);

namespace App\Command;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Uid\Uuid;

#[AsCommand(name: 'app:admin:create', description: 'Creer un compte administrateur avec un seul mot de passe de connexion.')]
final class CreateAdminAccountCommand extends Command
{
    public function __construct(private readonly EntityManagerInterface $em, private readonly UserPasswordHasherInterface $hasher)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('email', InputArgument::REQUIRED, 'Nouvelle adresse e-mail administrateur');
        $this->addOption('revoke-old', null, InputOption::VALUE_REQUIRED, 'Adresse du compte dont retirer ROLE_ADMIN apres creation');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        if (!$input->isInteractive()) {
            $io->error('Mode interactif requis : les mots de passe ne doivent pas figurer dans la commande.');
            return Command::FAILURE;
        }
        $email = strtolower(trim((string) $input->getArgument('email')));
        $oldEmail = $input->getOption('revoke-old');
        $oldEmail = is_string($oldEmail) ? strtolower(trim($oldEmail)) : null;
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 180) {
            $io->error('Adresse e-mail invalide.');
            return Command::FAILURE;
        }
        if ($oldEmail !== null && (!filter_var($oldEmail, FILTER_VALIDATE_EMAIL) || $oldEmail === $email)) {
            $io->error('Adresse de retrait invalide ou identique au nouveau compte.');
            return Command::FAILURE;
        }
        if ($this->em->getRepository(User::class)->findOneBy(['email' => $email])) {
            $io->error('Ce compte existe deja. Cette commande ne modifie pas les comptes existants.');
            return Command::FAILURE;
        }
        $oldUser = $oldEmail !== null ? $this->em->getRepository(User::class)->findOneBy(['email' => $oldEmail]) : null;
        if ($oldEmail !== null && (!$oldUser || !in_array('ROLE_ADMIN', $oldUser->getRoles(), true))) {
            $io->error('Le compte a retrograder est introuvable ou ne possede pas ROLE_ADMIN.');
            return Command::FAILURE;
        }
        $helper = $this->getHelper('question');
        $ask = static function (string $label) use ($helper, $input, $output): string {
            $question = new Question($label);
            $question->setHidden(true);
            $question->setHiddenFallback(false);
            return (string) $helper->ask($input, $output, $question);
        };
        $loginPassword = $ask('Mot de passe de connexion (20 caracteres minimum) : ');
        $loginConfirm = $ask('Confirmer le mot de passe de connexion : ');
        foreach ([[$loginPassword, $loginConfirm]] as [$password, $confirmation]) {
            $families = (int) preg_match('/[a-z]/', $password) + (int) preg_match('/[A-Z]/', $password)
                + (int) preg_match('/\d/', $password) + (int) preg_match('/[^a-zA-Z\d]/', $password);
            if (strlen($password) < 20 || strlen($password) > 1024 || $families < 3 || !hash_equals($password, $confirmation)) {
                $io->error('Le mot de passe doit comporter 20 caracteres minimum, 3 familles de caracteres et une confirmation identique.');
                return Command::FAILURE;
            }
        }
        if ($oldUser && !$io->confirm(sprintf('Retirer ROLE_ADMIN a %s apres creation de %s ?', $oldEmail, $email), false)) {
            $io->warning('Operation annulee : aucun compte modifie.');
            return Command::FAILURE;
        }
        $user = new User(Uuid::v4()->toRfc4122(), $email);
        $user->setPasswordHash($this->hasher->hashPassword($user, $loginPassword));
        $user->grantAdmin();
        $connection = $this->em->getConnection();
        $connection->beginTransaction();
        try {
            $this->em->persist($user);
            if ($oldUser) {
                $oldUser->revokeAdmin();
            }
            $this->em->flush();
            $connection->commit();
        } catch (\Throwable $e) {
            $connection->rollBack();
            $io->error('Creation annulee : '.$e->getMessage());
            return Command::FAILURE;
        }
        $io->success('Compte administrateur cree. Connectez-vous sur /login : redirection automatique vers /admin, sans mot de passe supplementaire.');
        if ($oldUser) $io->note('ROLE_ADMIN retire a '.$oldEmail.'. Ses sessions existantes doivent etre fermees.');
        return Command::SUCCESS;
    }
}
