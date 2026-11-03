<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactory;

$factory = new PasswordHasherFactory([
    User::class => [
        'algorithm' => 'argon2id',
        'migrate_from' => ['auto'],
    ],
]);
$hasher = $factory->getPasswordHasher(User::class);
$password = 'example-password-for-test';
$legacyHash = password_hash($password, PASSWORD_BCRYPT);

if (!$hasher->verify($legacyHash, $password) || !$hasher->needsRehash($legacyHash)) {
    throw new RuntimeException('Legacy password hashes must verify and require migration.');
}

$newHash = $hasher->hash($password);
if (!str_starts_with($newHash, '$argon2id$')) {
    throw new RuntimeException('New password hashes must use Argon2id.');
}

echo "OK Argon2id hashing and legacy hash migration\n";

$kernel = new App\Kernel('test', true);
$kernel->boot();
$repository = $kernel->getContainer()->get('doctrine')->getRepository(User::class);
if (!$repository instanceof UserRepository || !$repository instanceof PasswordUpgraderInterface) {
    throw new RuntimeException('The user provider repository must persist password upgrades after login.');
}
$kernel->shutdown();

echo "OK Doctrine user provider persists password upgrades\n";
