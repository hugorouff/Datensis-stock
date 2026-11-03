<?php

declare(strict_types=1);

namespace App\Command;

use App\Entity\User;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'app:user:delete', description: 'Supprimer definitivement un compte Datensis Stock et ses donnees associees.')]
final class DeleteUserAccountCommand extends Command
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('email', InputArgument::REQUIRED, 'Adresse e-mail exacte du compte a supprimer')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Afficher les donnees concernees sans les supprimer');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $email = strtolower(trim((string) $input->getArgument('email')));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 180) {
            $io->error('Adresse e-mail invalide.');
            return Command::FAILURE;
        }

        $user = $this->em->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            $io->error('Aucun compte correspondant. Aucune suppression effectuee.');
            return Command::FAILURE;
        }

        $conn = $this->em->getConnection();
        try {
            $counts = $this->counts($conn, $user->getId());
        } catch (\Throwable $e) {
            $io->error('Impossible de verifier les dependances : '.$e->getMessage());
            return Command::FAILURE;
        }

        $io->title('Suppression DEFINITIVE du compte '.$email);
        $io->table(['Donnees supprimees', 'Nombre'], array_map(
            static fn (string $table, int $count): array => [$table, (string) $count],
            array_keys($counts), array_values($counts)
        ));
        $io->warning('Suppression irreversible : coffre chiffre, Send, invitations, contributions, sessions d\'extension et partages crees ou recus. Sauvegardez la base avant de continuer.');

        if ($input->getOption('dry-run')) {
            $io->success('Simulation seulement : aucune donnee modifiee.');
            return Command::SUCCESS;
        }
        if (!$input->isInteractive()) {
            $io->error('Confirmation interactive obligatoire : relancez la commande sans --no-interaction.');
            return Command::FAILURE;
        }
        $expected = 'SUPPRIMER '.$email;
        $answer = (string) $io->ask('Pour confirmer, tapez exactement : '.$expected);
        if (!hash_equals($expected, $answer)) {
            $io->warning('Confirmation incorrecte. Aucune suppression effectuee.');
            return Command::FAILURE;
        }

        $conn->beginTransaction();
        try {
            // Revalider dans la transaction, notamment si le compte a change entre-temps.
            $row = $conn->fetchAssociative('SELECT id, roles FROM vault_user WHERE id = :id AND email = :email', ['id'=>$user->getId(), 'email'=>$email]);
            if (!$row) {
                throw new \RuntimeException('Compte introuvable au moment de la suppression.');
            }
            $roles = json_decode((string) $row['roles'], true);
            if (is_array($roles) && in_array('ROLE_ADMIN', $roles, true) && $this->countOtherAdmins($conn, $user->getId()) === 0) {
                throw new \RuntimeException('Refus de supprimer le dernier administrateur. Creez-en un autre avant.');
            }

            // Suppressions explicites : fonctionne meme lorsque SQLite ne verifie pas les cles etrangeres.
            // Toute erreur provoque un ROLLBACK des changements effectues dans cette transaction.
            $present = array_fill_keys(array_keys($this->knownTables($conn)), true);
            $id = $user->getId();
            if (isset($present['vault_share'])) {
                $conn->executeStatement('DELETE FROM vault_share WHERE owner_id = :id OR recipient_id = :id', ['id'=>$id]);
            }
            if (isset($present['vault_contribution']) && isset($present['vault_invitation'])) {
                $conn->executeStatement('DELETE FROM vault_contribution WHERE invitation_id IN (SELECT id FROM vault_invitation WHERE owner_id = :id)', ['id'=>$id]);
            }
            foreach (['vault_invitation', 'vault_entry', 'secure_send', 'vault_extension_session'] as $table) {
                if (isset($present[$table])) {
                    $conn->executeStatement('DELETE FROM '.$table.' WHERE owner_id = :id', ['id'=>$id]);
                }
            }
            $deleted = $conn->executeStatement('DELETE FROM vault_user WHERE id = :id AND email = :email', ['id'=>$id, 'email'=>$email]);
            if ($deleted !== 1) {
                throw new \RuntimeException('Le compte n\'a pas ete supprime : operation annulee.');
            }
            $conn->commit();
        } catch (\Throwable $e) {
            $conn->rollBack();
            $io->error('Suppression annulee et transaction restauree : '.$e->getMessage());
            return Command::FAILURE;
        }

        $this->em->clear();
        $io->success('Compte '.$email.' et donnees associees supprimes definitivement.');
        $io->note('Les sessions navigateur existantes peuvent rester en memoire jusqu\'a expiration, mais le compte ne peut plus etre authentifie.');
        return Command::SUCCESS;
    }

    /** @return array<string, true> */
    private function knownTables(Connection $conn): array
    {
        $all = $conn->createSchemaManager()->listTableNames();
        $known = ['vault_share', 'vault_contribution', 'vault_invitation', 'vault_entry', 'secure_send', 'vault_extension_session'];
        return array_fill_keys(array_values(array_intersect($known, $all)), true);
    }

    /** @return array<string, int> */
    private function counts(Connection $conn, string $id): array
    {
        $present = $this->knownTables($conn);
        $queries = [
            'Partages (emis ou recus)' => ['vault_share', 'SELECT COUNT(*) FROM vault_share WHERE owner_id = :id OR recipient_id = :id'],
            'Contributions recues' => ['vault_contribution', 'SELECT COUNT(*) FROM vault_contribution WHERE invitation_id IN (SELECT id FROM vault_invitation WHERE owner_id = :id)'],
            'Invitations' => ['vault_invitation', 'SELECT COUNT(*) FROM vault_invitation WHERE owner_id = :id'],
            'Elements du coffre' => ['vault_entry', 'SELECT COUNT(*) FROM vault_entry WHERE owner_id = :id'],
            'Liens Send' => ['secure_send', 'SELECT COUNT(*) FROM secure_send WHERE owner_id = :id'],
            'Sessions extension' => ['vault_extension_session', 'SELECT COUNT(*) FROM vault_extension_session WHERE owner_id = :id'],
        ];
        $result = [];
        foreach ($queries as $label => [$table, $sql]) {
            $result[$label] = isset($present[$table]) && ($table !== 'vault_contribution' || isset($present['vault_invitation']))
                ? (int) $conn->fetchOne($sql, ['id'=>$id]) : 0;
        }
        return $result;
    }

    private function countOtherAdmins(Connection $conn, string $excludedId): int
    {
        $rows = $conn->fetchAllAssociative('SELECT id, roles FROM vault_user WHERE id <> :id', ['id'=>$excludedId]);
        $admins = 0;
        foreach ($rows as $row) {
            $roles = json_decode((string) $row['roles'], true);
            if (is_array($roles) && in_array('ROLE_ADMIN', $roles, true)) {
                $admins++;
            }
        }
        return $admins;
    }
}
