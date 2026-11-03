<?php

declare(strict_types=1);

namespace App\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** Verifie/repare UNIQUEMENT la table des jetons temporaires de l'extension. */
#[AsCommand(name: 'app:extension:doctor', description: 'Vérifie la table des sessions de l’extension sans toucher au coffre chiffré.')]
final class ExtensionDoctorCommand extends Command
{
    private const MIGRATION = 'DoctrineMigrations\\Version20261028000400';
    private const REQUIRED_COLUMNS = ['id', 'owner_id', 'token_hash', 'expires_at'];

    public function __construct(private readonly Connection $connection)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('repair', null, InputOption::VALUE_NONE, 'Créer uniquement la table/index de sessions manquants (sans supprimer de données).');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $platform = $this->connection->getDatabasePlatform();
            if (!$platform instanceof SqlitePlatform && !$platform instanceof PostgreSQLPlatform) {
                $output->writeln('<error>Seuls SQLite et PostgreSQL sont pris en charge.</error>');
                return Command::FAILURE;
            }
            $schema = $this->connection->createSchemaManager();
            if (!$schema->tablesExist(['vault_user'])) {
                $output->writeln('<error>La table des utilisateurs est absente. Vérifiez la base configurée.</error>');
                return Command::FAILURE;
            }
            $hasSessions = $schema->tablesExist(['vault_extension_session']);
            if (!$hasSessions) {
                $output->writeln('<comment>Table vault_extension_session absente de la base réellement utilisée.</comment>');
                if (!$input->getOption('repair')) {
                    $output->writeln('Exécutez d’abord php bin/console doctrine:migrations:migrate, puis relancez avec --repair si nécessaire.');
                    return Command::FAILURE;
                }
                if (!$schema->tablesExist(['doctrine_migration_versions'])) {
                    $output->writeln('<error>Historique des migrations absent : exécutez les migrations normalement.</error>');
                    return Command::FAILURE;
                }
                $migrated = $this->connection->fetchOne(
                    'SELECT version FROM doctrine_migration_versions WHERE version = :version',
                    ['version' => self::MIGRATION]
                );
                if ($migrated === false) {
                    $output->writeln('<error>La migration 00400 n’est pas enregistrée : utilisez doctrine:migrations:migrate.</error>');
                    return Command::FAILURE;
                }
                $this->connection->executeStatement('CREATE TABLE IF NOT EXISTS vault_extension_session (
                    id VARCHAR(36) NOT NULL PRIMARY KEY,
                    owner_id VARCHAR(36) NOT NULL,
                    token_hash VARCHAR(64) NOT NULL,
                    expires_at INTEGER NOT NULL,
                    FOREIGN KEY (owner_id) REFERENCES vault_user (id) ON DELETE CASCADE
                )');
                $output->writeln('<info>Table des sessions créée.</info>');
                $schema = $this->connection->createSchemaManager();
            }
            $columns = array_map(static fn ($column): string => strtolower($column->getName()), $schema->listTableColumns('vault_extension_session'));
            $missing = array_diff(self::REQUIRED_COLUMNS, $columns);
            if ($missing !== []) {
                $output->writeln('<error>Structure inattendue : colonnes manquantes : ' . implode(', ', $missing) . '. Aucune modification automatique.</error>');
                return Command::FAILURE;
            }

            $indices = [
                'uniq_vault_ext_token' => 'CREATE UNIQUE INDEX IF NOT EXISTS uniq_vault_ext_token ON vault_extension_session (token_hash)',
                'idx_vault_ext_owner' => 'CREATE INDEX IF NOT EXISTS idx_vault_ext_owner ON vault_extension_session (owner_id)',
                'idx_vault_ext_expiration' => 'CREATE INDEX IF NOT EXISTS idx_vault_ext_expiration ON vault_extension_session (expires_at)',
            ];
            $present = array_map(static fn ($index): string => strtolower($index->getName()), $schema->listTableIndexes('vault_extension_session'));
            $missingIndexes = array_diff(array_keys($indices), $present);
            if ($missingIndexes !== []) {
                if (!$input->getOption('repair')) {
                    $output->writeln('<comment>Index manquants : ' . implode(', ', $missingIndexes) . '. Lancez --repair pour les créer.</comment>');
                    return Command::FAILURE;
                }
                foreach ($missingIndexes as $name) {
                    $this->connection->executeStatement($indices[$name]);
                }
                $output->writeln('<info>Index manquants créés.</info>');
            }
            $output->writeln('<info>OK : table et index des sessions de l’extension disponibles. Aucun coffre modifié.</info>');
            return Command::SUCCESS;
        } catch (\Throwable $exception) {
            $output->writeln('<error>Vérification impossible : ' . $exception->getMessage() . '</error>');
            return Command::FAILURE;
        }
    }
}
