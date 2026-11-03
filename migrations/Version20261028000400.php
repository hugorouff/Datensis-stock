<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261028000400 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Sessions courtes pour les extensions : jetons haches, jamais les mots de passe.';
    }

    public function up(Schema $schema): void
    {
        $platform = $this->connection->getDatabasePlatform();
        if (!$platform instanceof SqlitePlatform && !$platform instanceof PostgreSQLPlatform) {
            throw new \RuntimeException('Seuls SQLite et PostgreSQL sont pris en charge.');
        }

        $this->addSql('CREATE TABLE vault_extension_session (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            owner_id VARCHAR(36) NOT NULL,
            token_hash VARCHAR(64) NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES vault_user (id) ON DELETE CASCADE
        )');
        $this->addSql('CREATE UNIQUE INDEX uniq_vault_ext_token ON vault_extension_session (token_hash)');
        $this->addSql('CREATE INDEX idx_vault_ext_owner ON vault_extension_session (owner_id)');
        $this->addSql('CREATE INDEX idx_vault_ext_expiration ON vault_extension_session (expires_at)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE vault_extension_session');
    }
}
