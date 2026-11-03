<?php

declare(strict_types=1);

namespace App\Service;

use App\Entity\User;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Uid\Uuid;

/** Operations metadata only: never returns or reads decrypted vault items. */
final class AdminAccountService
{
    public function __construct(private readonly EntityManagerInterface $em) {}

    public function audit(string $actorEmail, string $subjectEmail, string $action, array $details = []): void
    {
        // Never include passwords, encrypted payloads, keys or security answers in audit entries.
        $this->em->getConnection()->insert('vault_admin_audit', [
            'id' => Uuid::v4()->toRfc4122(),
            'actor_email' => $actorEmail,
            'subject_email' => $subjectEmail,
            'action' => $action,
            'details' => json_encode($details, JSON_THROW_ON_ERROR),
            'created_at' => gmdate('Y-m-d H:i:s'),
        ]);
    }

    public function otherAdminsCount(string $excludedId): int
    {
        $rows = $this->em->getConnection()->fetchAllAssociative(
            'SELECT roles FROM vault_user WHERE id <> :id AND disabled_at IS NULL', ['id' => $excludedId]
        );
        $count = 0;
        foreach ($rows as $row) {
            $roles = json_decode((string) $row['roles'], true);
            if (is_array($roles) && in_array('ROLE_ADMIN', $roles, true)) $count++;
        }
        return $count;
    }

    public function userCounts(string $id): array
    {
        $conn = $this->em->getConnection();
        $queries = [
            'entries' => 'SELECT COUNT(*) FROM vault_entry WHERE owner_id=:id',
            'sends' => 'SELECT COUNT(*) FROM secure_send WHERE owner_id=:id',
            'invitations' => 'SELECT COUNT(*) FROM vault_invitation WHERE owner_id=:id',
            'shares' => 'SELECT COUNT(*) FROM vault_share WHERE owner_id=:id OR recipient_id=:id',
            'sessions' => 'SELECT COUNT(*) FROM vault_extension_session WHERE owner_id=:id',
        ];
        $counts = [];
        foreach ($queries as $key => $sql) $counts[$key] = (int) $conn->fetchOne($sql, ['id' => $id]);
        return $counts;
    }

    public function canResetPassword(User $user): bool
    {
        if ($user->getVaultSalt() !== null || $user->getVaultCheck() !== null ||
            $user->getSharingPublicKey() !== null || $user->getSharingPrivateKey() !== null) return false;
        $counts = $this->userCounts($user->getId());
        return $counts['entries'] === 0 && $counts['sends'] === 0 && $counts['invitations'] === 0 && $counts['shares'] === 0;
    }

    /** Hard deletion with explicit dependent-row cleanup for SQLite even if foreign keys are disabled. */
    public function deleteUser(User $user, User $actor, string $expectedEmail): array
    {
        if ($user->getId() === $actor->getId()) throw new \DomainException('Impossible de supprimer votre propre compte.');
        $conn = $this->em->getConnection();
        return $conn->transactional(function (Connection $conn) use ($user, $actor, $expectedEmail): array {
            $row = $conn->fetchAssociative('SELECT id,email,roles FROM vault_user WHERE id=:id AND email=:email', [
                'id' => $user->getId(), 'email' => $expectedEmail,
            ]);
            if (!$row) throw new \DomainException('Compte modifie ou deja supprime. Actualisez la liste.');
            $roles = json_decode((string) $row['roles'], true);
            if (is_array($roles) && in_array('ROLE_ADMIN', $roles, true) && $this->otherAdminsCount($user->getId()) === 0) {
                throw new \DomainException('Impossible de supprimer le dernier administrateur actif.');
            }
            $counts = $this->userCounts($user->getId());
            $id = $user->getId();
            $conn->executeStatement('DELETE FROM vault_share WHERE owner_id=:id OR recipient_id=:id', ['id' => $id]);
            $conn->executeStatement('DELETE FROM vault_contribution WHERE invitation_id IN (SELECT id FROM vault_invitation WHERE owner_id=:id)', ['id' => $id]);
            foreach (['vault_invitation', 'vault_entry', 'secure_send', 'vault_extension_session'] as $table) {
                $conn->executeStatement('DELETE FROM '.$table.' WHERE owner_id=:id', ['id' => $id]);
            }
            if ($conn->executeStatement('DELETE FROM vault_user WHERE id=:id AND email=:email', ['id'=>$id, 'email'=>$expectedEmail]) !== 1) {
                throw new \RuntimeException('Suppression annulee.');
            }
            // Le compte est totalement retire. Neutraliser son e-mail dans l'historique,
            // mais conserver une trace non nominative de l'action pour la securite.
            $anonymous = 'deleted:'.substr(hash('sha256', $id), 0, 20);
            $conn->executeStatement('UPDATE vault_admin_audit SET subject_email=:anon WHERE subject_email=:email', ['anon'=>$anonymous, 'email'=>$expectedEmail]);
            $conn->executeStatement('UPDATE vault_admin_audit SET actor_email=:anon WHERE actor_email=:email', ['anon'=>$anonymous, 'email'=>$expectedEmail]);
            $this->audit($actor->getEmail(), $anonymous, 'user.deleted', $counts);
            return $counts;
        });
    }
}
