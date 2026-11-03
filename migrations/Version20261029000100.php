<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261029000100 extends AbstractMigration
{
    public function getDescription(): string { return 'Administration renforcee et invitations individuelles chiffrees, sans toucher aux secrets existants.'; }
    public function up(Schema $schema): void
    {
        $platform = $this->connection->getDatabasePlatform();
        if (!$platform instanceof SqlitePlatform && !$platform instanceof PostgreSQLPlatform) throw new \RuntimeException('SQLite et PostgreSQL uniquement.');
        $date = $platform instanceof PostgreSQLPlatform ? 'TIMESTAMP(0) WITHOUT TIME ZONE' : 'DATETIME';
        $this->addSql('ALTER TABLE vault_user ADD COLUMN admin_password_hash VARCHAR(255) DEFAULT NULL');
        $this->addSql("CREATE TABLE vault_invitation (
            id VARCHAR(36) NOT NULL PRIMARY KEY, owner_id VARCHAR(36) NOT NULL,
            token_hash VARCHAR(64) NOT NULL UNIQUE, recipient_email VARCHAR(180) NOT NULL,
            company_folder VARCHAR(360) NOT NULL, public_key TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL, expires_at $date NOT NULL, created_at $date NOT NULL,
            otp_hash VARCHAR(64) DEFAULT NULL, otp_session_hash VARCHAR(64) DEFAULT NULL,
            otp_expires_at $date DEFAULT NULL, otp_attempts INTEGER NOT NULL DEFAULT 0,
            consented_at $date DEFAULT NULL, redeemed_at $date DEFAULT NULL, revoked_at $date DEFAULT NULL,
            FOREIGN KEY (owner_id) REFERENCES vault_user (id) ON DELETE CASCADE
        )");
        $this->addSql('CREATE INDEX idx_vault_invitation_owner ON vault_invitation (owner_id)');
        $this->addSql("CREATE TABLE vault_contribution (
            id VARCHAR(36) NOT NULL PRIMARY KEY, invitation_id VARCHAR(36) NOT NULL UNIQUE,
            ciphertext TEXT NOT NULL, created_at $date NOT NULL, imported_at $date DEFAULT NULL,
            FOREIGN KEY (invitation_id) REFERENCES vault_invitation (id) ON DELETE CASCADE
        )");
    }
    public function down(Schema $schema): void
    {
        throw new \RuntimeException('Descente refusee : risque de perte de contributions chiffrees.');
    }
}
