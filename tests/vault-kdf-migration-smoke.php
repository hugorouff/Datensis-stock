<?php

declare(strict_types=1);

$connection = new PDO('sqlite::memory:');
$connection->exec('CREATE TABLE vault_user (id VARCHAR(36) NOT NULL PRIMARY KEY, vault_salt VARCHAR(64) DEFAULT NULL, vault_check TEXT DEFAULT NULL)');
$connection->exec("INSERT INTO vault_user (id) VALUES ('legacy-user')");
$connection->exec('ALTER TABLE vault_user ADD COLUMN vault_kdf_version INTEGER NOT NULL DEFAULT 1');

$version = $connection->query("SELECT vault_kdf_version FROM vault_user WHERE id = 'legacy-user'")->fetchColumn();
if ((int) $version !== 1) {
    throw new RuntimeException('Existing vaults must be marked as PBKDF2 version 1.');
}

echo "OK legacy vault KDF version defaults to PBKDF2\n";
