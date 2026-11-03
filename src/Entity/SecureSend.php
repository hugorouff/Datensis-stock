<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'secure_send')]
class SecureSend
{
    #[ORM\Id]
    #[ORM\Column(length: 36)]
    private string $id;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private User $owner;

    #[ORM\Column(length: 64, unique: true)]
    private string $tokenHash;

    #[ORM\Column(length: 8)]
    private string $kind;

    #[ORM\Column(type: 'text')]
    private string $payload;

    #[ORM\Column(type: 'text')]
    private string $ownerPayload;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $passwordHash;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column]
    private int $views = 0;

    #[ORM\Column(nullable: true)]
    private ?int $maxViews;

    #[ORM\Column]
    private bool $disabled = false;

    public function __construct(
        string $id, User $owner, string $tokenHash, string $kind,
        string $payload, string $ownerPayload, ?string $passwordHash,
        \DateTimeImmutable $expiresAt, ?int $maxViews
    ) {
        $this->id = $id;
        $this->owner = $owner;
        $this->tokenHash = $tokenHash;
        $this->kind = $kind;
        $this->payload = $payload;
        $this->ownerPayload = $ownerPayload;
        $this->passwordHash = $passwordHash;
        $this->expiresAt = $expiresAt;
        $this->maxViews = $maxViews;
        $this->createdAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function getId(): string { return $this->id; }
    public function getOwner(): User { return $this->owner; }
    public function getKind(): string { return $this->kind; }
    public function getTokenHash(): string { return $this->tokenHash; }
    public function getPayload(): string { return $this->payload; }
    public function getOwnerPayload(): string { return $this->ownerPayload; }
    public function getPasswordHash(): ?string { return $this->passwordHash; }
    public function getExpiresAt(): \DateTimeImmutable { return $this->expiresAt; }
    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function getViews(): int { return $this->views; }
    public function getMaxViews(): ?int { return $this->maxViews; }
    public function isDisabled(): bool { return $this->disabled; }
    public function setDisabled(bool $disabled): void { $this->disabled = $disabled; }
}
