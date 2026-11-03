<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261028000100 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Tables utilisateurs et elements chiffres (SQLite / PostgreSQL).';
    }

    public function up(Schema $schema): void
    {
        $platform = $this->connection->getDatabasePlatform();
        if (!$platform instanceof SqlitePlatform && !$platform instanceof PostgreSQLPlatform) {
            throw new \RuntimeException('Cette migration prend en charge SQLite et PostgreSQL.');
        }

        $timestamp = $platform instanceof PostgreSQLPlatform ? 'TIMESTAMP(0) WITHOUT TIME ZONE' : 'DATETIME';
        $jsonType = $platform instanceof PostgreSQLPlatform ? 'JSON' : 'TEXT';
        $this->addSql("CREATE TABLE vault_user (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            email VARCHAR(180) NOT NULL,
            roles $jsonType NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            vault_salt VARCHAR(64) DEFAULT NULL,
            vault_check TEXT DEFAULT NULL
        )");
        $this->addSql('CREATE UNIQUE INDEX uniq_vault_user_email ON vault_user (email)');
        $this->addSql("CREATE TABLE vault_entry (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            owner_id VARCHAR(36) NOT NULL,
            encrypted_payload TEXT NOT NULL,
            created_at $timestamp NOT NULL,
            updated_at $timestamp NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES vault_user (id) ON DELETE CASCADE
        )");
        $this->addSql('CREATE INDEX idx_vault_entry_owner ON vault_entry (owner_id)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE vault_entry');
        $this->addSql('DROP TABLE vault_user');
    }
}
