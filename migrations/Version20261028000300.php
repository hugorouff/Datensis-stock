<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261028000300 extends AbstractMigration
{
    public function getDescription(): string { return 'Ajout TOTP et codes de recuperation, sans supprimer les coffres'; }

    public function up(Schema $schema): void
    {
        $this->addSql('ALTER TABLE vault_user ADD COLUMN totp_secret TEXT DEFAULT NULL');
        $this->addSql('ALTER TABLE vault_user ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT -1');
        $this->addSql('ALTER TABLE vault_user ADD COLUMN recovery_codes CLOB DEFAULT NULL');
    }

    public function down(Schema $schema): void
    {
        // Descente volontairement refusee : supprimer ces colonnes pourrait detruire la 2FA.
        throw new \RuntimeException('Cette migration de securite ne peut pas etre annulee automatiquement.');
    }
}
