<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261028000200 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Send : textes/fichiers chiffres, dates de suppression et limites d acces.';
    }

    public function up(Schema $schema): void
    {
        $pg = $this->connection->getDatabasePlatform() instanceof PostgreSQLPlatform;
        if (!$pg && !$this->connection->getDatabasePlatform() instanceof SqlitePlatform) {
            throw new \RuntimeException('SQLite et PostgreSQL uniquement.');
        }
        $date = $pg ? 'TIMESTAMP(0) WITHOUT TIME ZONE' : 'DATETIME';
        $boolean = $pg ? 'BOOLEAN' : 'BOOLEAN';
        $this->addSql("CREATE TABLE secure_send (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            owner_id VARCHAR(36) NOT NULL,
            token_hash VARCHAR(64) NOT NULL,
            kind VARCHAR(8) NOT NULL,
            payload TEXT NOT NULL,
            owner_payload TEXT NOT NULL,
            password_hash VARCHAR(255) DEFAULT NULL,
            expires_at $date NOT NULL,
            created_at $date NOT NULL,
            views INTEGER NOT NULL DEFAULT 0,
            max_views INTEGER DEFAULT NULL,
            disabled $boolean NOT NULL DEFAULT FALSE,
            FOREIGN KEY (owner_id) REFERENCES vault_user(id) ON DELETE CASCADE
        )");
        $this->addSql('CREATE UNIQUE INDEX uniq_secure_send_token ON secure_send (token_hash)');
        $this->addSql('CREATE INDEX idx_secure_send_owner ON secure_send (owner_id)');
        $this->addSql('CREATE INDEX idx_secure_send_expiry ON secure_send (expires_at)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE secure_send');
    }
}
