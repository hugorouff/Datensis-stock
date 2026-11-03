<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'vault_invitation')]
class VaultInvitation
{
    #[ORM\Id]
    #[ORM\Column(length: 36)]
    private string $id;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(name: 'owner_id', referencedColumnName: 'id', nullable: false, onDelete: 'CASCADE')]
    private User $owner;

    #[ORM\Column(length: 64, unique: true)]
    private string $tokenHash;

    #[ORM\Column(length: 180)]
    private string $recipientEmail;

    #[ORM\Column(length: 360)]
    private string $companyFolder;

    #[ORM\Column(type: 'text')]
    private string $publicKey;

    #[ORM\Column(type: 'text')]
    private string $encryptedPrivateKey;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(length: 64, nullable: true)]
    private ?string $otpHash = null;

    #[ORM\Column(length: 64, nullable: true)]
    private ?string $otpSessionHash = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $otpExpiresAt = null;

    #[ORM\Column(type: 'integer')]
    private int $otpAttempts = 0;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $consentedAt = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $redeemedAt = null;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $revokedAt = null;

    public function __construct(string $id, User $owner, string $tokenHash, string $recipientEmail, string $companyFolder, string $publicKey, string $encryptedPrivateKey, \DateTimeImmutable $expiresAt)
    {
        $this->id = $id;
        $this->owner = $owner;
        $this->tokenHash = $tokenHash;
        $this->recipientEmail = strtolower(trim($recipientEmail));
        $this->companyFolder = $companyFolder;
        $this->publicKey = $publicKey;
        $this->encryptedPrivateKey = $encryptedPrivateKey;
        $this->expiresAt = $expiresAt;
        $this->createdAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function getId(): string { return $this->id; }
    public function getOwner(): User { return $this->owner; }
    public function getRecipientEmail(): string { return $this->recipientEmail; }
    public function getCompanyFolder(): string { return $this->companyFolder; }
    public function getPublicKey(): string { return $this->publicKey; }
    public function getEncryptedPrivateKey(): string { return $this->encryptedPrivateKey; }
    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function getExpiresAt(): \DateTimeImmutable { return $this->expiresAt; }
    public function getRedeemedAt(): ?\DateTimeImmutable { return $this->redeemedAt; }
    public function getRevokedAt(): ?\DateTimeImmutable { return $this->revokedAt; }
    public function getOtpAttempts(): int { return $this->otpAttempts; }
    public function getOtpSessionHash(): ?string { return $this->otpSessionHash; }
    public function getOtpExpiresAt(): ?\DateTimeImmutable { return $this->otpExpiresAt; }
    public function getConsentedAt(): ?\DateTimeImmutable { return $this->consentedAt; }
    public function isUsable(): bool { return !$this->redeemedAt && !$this->revokedAt && $this->expiresAt > new \DateTimeImmutable('now', new \DateTimeZone('UTC')); }
    public function markConsent(): void { $this->consentedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC')); }
    public function issueOtp(string $hash, string $sessionHash): void
    {
        $this->otpHash = $hash;
        $this->otpSessionHash = $sessionHash;
        $this->otpExpiresAt = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify('+10 minutes');
        $this->otpAttempts = 0;
    }
    public function verifyOtp(string $hash, string $sessionHash): bool
    {
        $this->otpAttempts++;
        if ($this->otpAttempts > 5 || !$this->otpHash || !$this->otpExpiresAt || $this->otpExpiresAt < new \DateTimeImmutable('now', new \DateTimeZone('UTC')) || !$this->otpSessionHash || !hash_equals($this->otpSessionHash, $sessionHash)) return false;
        if (!hash_equals($this->otpHash, $hash)) return false;
        $this->otpHash = null;
        $this->otpExpiresAt = null;
        $this->otpSessionHash = null;
        return true;
    }
    public function revoke(): void { $this->revokedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC')); }
    public function redeem(): void { $this->redeemedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC')); }
}
