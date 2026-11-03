<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261103000100 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Versionne la derivation des cles de coffre pour migrer PBKDF2 vers Argon2id.';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('ALTER TABLE vault_user ADD COLUMN vault_kdf_version INTEGER NOT NULL DEFAULT 1');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('ALTER TABLE vault_user DROP COLUMN vault_kdf_version');
    }
}
