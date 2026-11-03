<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'vault_entry')]
#[ORM\Index(name: 'idx_vault_entry_owner', columns: ['owner_id'])]
final class VaultEntry
{
    #[ORM\Id]
    #[ORM\Column(length: 36)]
    private string $id;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(name: 'owner_id', referencedColumnName: 'id', nullable: false, onDelete: 'CASCADE')]
    private User $owner;

    // JSON AEAD: {v, iv, data}, uniquement chiffre dans la base.
    #[ORM\Column(type: 'text')]
    private string $encryptedPayload;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $updatedAt;

    public function __construct(string $id, User $owner, string $encryptedPayload)
    {
        $this->id = $id;
        $this->owner = $owner;
        $this->encryptedPayload = $encryptedPayload;
        $this->createdAt = $this->updatedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function getId(): string { return $this->id; }
    public function getOwner(): User { return $this->owner; }
    public function getEncryptedPayload(): string { return $this->encryptedPayload; }
    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function getUpdatedAt(): \DateTimeImmutable { return $this->updatedAt; }

    public function replacePayload(string $encryptedPayload): void
    {
        $this->encryptedPayload = $encryptedPayload;
        $this->updatedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }
}
