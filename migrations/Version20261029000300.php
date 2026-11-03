<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SqlitePlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261029000300 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Gestion des comptes, desactivations, premiere connexion et journal admin (aucun secret).';
    }

    public function up(Schema $schema): void
    {
        $platform = $this->connection->getDatabasePlatform();
        if (!$platform instanceof SqlitePlatform && !$platform instanceof PostgreSQLPlatform) {
            throw new \RuntimeException('SQLite et PostgreSQL uniquement.');
        }
        $date = $platform instanceof PostgreSQLPlatform ? 'TIMESTAMP(0) WITHOUT TIME ZONE' : 'DATETIME';
        $this->addSql("ALTER TABLE vault_user ADD COLUMN disabled_at $date DEFAULT NULL");
        $this->addSql('ALTER TABLE vault_user ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE');
        $this->addSql("ALTER TABLE vault_user ADD COLUMN created_at $date DEFAULT NULL");
        $this->addSql("ALTER TABLE vault_user ADD COLUMN last_login_at $date DEFAULT NULL");
        $this->addSql("CREATE TABLE vault_admin_audit (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            actor_email VARCHAR(180) NOT NULL,
            subject_email VARCHAR(180) NOT NULL,
            action VARCHAR(48) NOT NULL,
            details TEXT NOT NULL,
            created_at $date NOT NULL
        )");
        $this->addSql('CREATE INDEX idx_vault_audit_created ON vault_admin_audit (created_at)');
    }

    public function down(Schema $schema): void
    {
        throw new \RuntimeException('Historique administrateur et etats des comptes : migration non reversible automatiquement.');
    }
}
