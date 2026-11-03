<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'vault_contribution')]
class VaultContribution
{
    #[ORM\Id]
    #[ORM\Column(length: 36)]
    private string $id;

    #[ORM\OneToOne(targetEntity: VaultInvitation::class)]
    #[ORM\JoinColumn(name: 'invitation_id', referencedColumnName: 'id', nullable: false, onDelete: 'CASCADE', unique: true)]
    private VaultInvitation $invitation;

    #[ORM\Column(type: 'text')]
    private string $ciphertext;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $importedAt = null;

    public function __construct(string $id, VaultInvitation $invitation, string $ciphertext)
    {
        $this->id = $id; $this->invitation = $invitation; $this->ciphertext = $ciphertext;
        $this->createdAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }
    public function getInvitation(): VaultInvitation { return $this->invitation; }
    public function getId(): string { return $this->id; }
    public function getCiphertext(): string { return $this->ciphertext; }
    public function getImportedAt(): ?\DateTimeImmutable { return $this->importedAt; }
    public function markImported(): void { $this->importedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC')); }
}
