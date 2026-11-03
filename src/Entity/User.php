<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'vault_user')]
#[ORM\UniqueConstraint(name: 'uniq_vault_user_email', columns: ['email'])]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\Column(length: 36)]
    private string $id;

    #[ORM\Column(length: 180)]
    private string $email;

    #[ORM\Column(type: 'json')]
    private array $roles = [];

    #[ORM\Column(length: 255)]
    private string $passwordHash;

    // Salt et verificateur du coffre: jamais la phrase secrete.
    #[ORM\Column(length: 64, nullable: true)]
    private ?string $vaultSalt = null;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $vaultCheck = null;

    #[ORM\Column(type: 'integer', options: ['default' => 1])]
    private int $vaultKdfVersion = 1;

    // Secret TOTP chiffre au repos avec APP_SECRET (pas la cle du coffre).
    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $totpSecret = null;

    #[ORM\Column(type: 'integer', options: ['default' => -1])]
    private int $totpLastStep = -1;

    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $recoveryCodes = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $adminPasswordHash = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $disabledAt = null;

    #[ORM\Column(type: 'boolean', options: ['default' => false])]
    private bool $mustChangePassword = false;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastLoginAt = null;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $sharingPublicKey = null;

    #[ORM\Column(type: 'text', nullable: true)]
    private ?string $sharingPrivateKey = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $sharingEmailVerifiedAt = null;

    public function getSharingPublicKey(): ?string { return $this->sharingPublicKey; }
    public function getSharingPrivateKey(): ?string { return $this->sharingPrivateKey; }
    public function getSharingEmailVerifiedAt(): ?\DateTimeImmutable { return $this->sharingEmailVerifiedAt; }
    public function setSharingKeys(string $public, string $encryptedPrivate): void {
        if ($this->sharingPublicKey !== null || $this->sharingPrivateKey !== null) {
            throw new \LogicException('Cles de partage deja creees.');
        }
        $this->sharingPublicKey = $public;
        $this->sharingPrivateKey = $encryptedPrivate;
    }
    public function replaceSharingPrivateKey(string $encryptedPrivate): void { $this->sharingPrivateKey = $encryptedPrivate; }
    public function verifySharingEmail(): void { $this->sharingEmailVerifiedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC')); }

    public function getAdminPasswordHash(): ?string { return $this->adminPasswordHash; }
    public function setAdminPasswordHash(string $hash): void { $this->adminPasswordHash = $hash; }
    public function grantAdmin(): void { $this->roles = array_values(array_unique([...$this->roles, 'ROLE_ADMIN'])); }
    public function revokeAdmin(): void { $this->roles = array_values(array_diff($this->roles, ['ROLE_ADMIN'])); }
    public function setEmail(string $email): void { $this->email = strtolower(trim($email)); }
    public function getDisabledAt(): ?\DateTimeImmutable { return $this->disabledAt; }
    public function isDisabled(): bool { return $this->disabledAt !== null; }
    public function setDisabled(bool $disabled): void {
        $this->disabledAt = $disabled ? ($this->disabledAt ?? new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) : null;
    }
    public function needsPasswordChange(): bool { return $this->mustChangePassword; }
    public function requirePasswordChange(): void { $this->mustChangePassword = true; }
    public function finishPasswordChange(): void { $this->mustChangePassword = false; }
    public function getCreatedAt(): ?\DateTimeImmutable { return $this->createdAt; }
    public function getLastLoginAt(): ?\DateTimeImmutable { return $this->lastLoginAt; }
    public function markLastLogin(): void { $this->lastLoginAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC')); }

    public function isTotpEnabled(): bool { return $this->totpSecret !== null; }
    public function getTotpSecret(): ?string { return $this->totpSecret; }
    public function getTotpLastStep(): int { return $this->totpLastStep; }
    public function getRecoveryCodes(): array { return $this->recoveryCodes ?? []; }
    public function consumeTotpStep(int $step): void { $this->totpLastStep = $step; }
    public function consumeRecoveryCode(string $hash): void {
        $this->recoveryCodes = array_values(array_filter($this->recoveryCodes ?? [], static fn(string $v): bool => !hash_equals($v, $hash)));
    }
    public function enableTotp(string $encryptedSecret, array $hashes, int $lastStep): void {
        $this->totpSecret = $encryptedSecret;
        $this->recoveryCodes = $hashes;
        $this->totpLastStep = $lastStep;
    }
    public function disableTotp(): void {
        $this->totpSecret = null;
        $this->recoveryCodes = null;
        $this->totpLastStep = -1;
    }

    public function __construct(string $id, string $email)
    {
        $this->id = $id;
        $this->email = strtolower(trim($email));
        $this->createdAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function getId(): string { return $this->id; }
    public function getEmail(): string { return $this->email; }
    public function getUserIdentifier(): string { return $this->email; }
    public function getRoles(): array { return array_unique([...$this->roles, 'ROLE_USER']); }
    public function getPassword(): ?string { return $this->passwordHash; }
    public function setPasswordHash(string $hash): void { $this->passwordHash = $hash; }
    public function eraseCredentials(): void {}
    public function getVaultSalt(): ?string { return $this->vaultSalt; }
    public function getVaultCheck(): ?string { return $this->vaultCheck; }
    public function getVaultKdfVersion(): int { return $this->vaultKdfVersion; }

    public function initializeVault(string $salt, string $check, int $kdfVersion = 1): void
    {
        if ($this->vaultSalt !== null || $this->vaultCheck !== null) {
            throw new \LogicException('Coffre deja initialise.');
        }
        $this->vaultSalt = $salt;
        $this->vaultCheck = $check;
        $this->vaultKdfVersion = $kdfVersion;
    }

    public function replaceVaultMetadata(string $salt, string $check, int $kdfVersion = 1): void
    {
        $this->vaultSalt = $salt;
        $this->vaultCheck = $check;
        $this->vaultKdfVersion = $kdfVersion;
    }

    public function __serialize(): array
    {
        $data = (array) $this;
        // Ne jamais placer le hash de connexion dans la session.
        $data["\0".self::class."\0passwordHash"] = hash('crc32c', $this->passwordHash);
        // Le hash du second facteur administratif ne doit pas etre serialise dans la session.
        $data["\0".self::class."\0adminPasswordHash"] = $this->adminPasswordHash === null ? null : hash('crc32c', $this->adminPasswordHash);
        return $data;
    }
}
