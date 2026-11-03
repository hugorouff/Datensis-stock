<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261029000200 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Partages prives entre comptes par adresse e-mail, consentement et enveloppes chiffrees.';
    }

    public function up(Schema $schema): void
    {
        $platform = $this->connection->getDatabasePlatform();
        if (!$platform instanceof SqlitePlatform && !$platform instanceof PostgreSQLPlatform) {
            throw new \RuntimeException('SQLite et PostgreSQL uniquement.');
        }
        $date = $platform instanceof PostgreSQLPlatform ? 'TIMESTAMP(0) WITHOUT TIME ZONE' : 'DATETIME';
        $this->addSql('ALTER TABLE vault_user ADD COLUMN sharing_public_key TEXT DEFAULT NULL');
        $this->addSql('ALTER TABLE vault_user ADD COLUMN sharing_private_key TEXT DEFAULT NULL');
        $this->addSql("ALTER TABLE vault_user ADD COLUMN sharing_email_verified_at $date DEFAULT NULL");
        $this->addSql("CREATE TABLE vault_share (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            owner_id VARCHAR(36) NOT NULL,
            recipient_id VARCHAR(36) NOT NULL,
            scope_type VARCHAR(12) NOT NULL,
            owner_metadata TEXT NOT NULL,
            encrypted_bundle TEXT NOT NULL,
            created_at $date NOT NULL,
            updated_at $date NOT NULL,
            accepted_at $date DEFAULT NULL,
            consent_version VARCHAR(20) DEFAULT NULL,
            declined_at $date DEFAULT NULL,
            revoked_at $date DEFAULT NULL,
            FOREIGN KEY (owner_id) REFERENCES vault_user (id) ON DELETE CASCADE,
            FOREIGN KEY (recipient_id) REFERENCES vault_user (id) ON DELETE CASCADE
        )");
        $this->addSql('CREATE INDEX idx_vault_share_owner ON vault_share (owner_id)');
        $this->addSql('CREATE INDEX idx_vault_share_recipient ON vault_share (recipient_id)');
        $this->addSql('CREATE INDEX idx_vault_share_status ON vault_share (recipient_id, accepted_at, revoked_at)');
    }

    public function down(Schema $schema): void
    {
        throw new \RuntimeException('Migration irreversible : ne pas effacer les partages et les cles chiffrees.');
    }
}
