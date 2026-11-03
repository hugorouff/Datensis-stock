<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Entity\VaultEntry;
use App\Entity\VaultInvitation;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

#[Route('/api/vault')]
final class VaultApiController extends AbstractController
{
    private function currentUser(): User
    {
        $user = $this->getUser();
        if (!$user instanceof User) {
            throw $this->createAccessDeniedException();
        }
        return $user;
    }

    private function respond(array $data, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store, private');
        return $response;
    }

    private function verifyMutation(Request $request): bool
    {
        return $this->isCsrfTokenValid('vault_api', (string) $request->headers->get('X-CSRF-Token', ''));
    }

    private function jsonBody(Request $request): ?array
    {
        if (strlen($request->getContent()) > 40_000) {
            return null;
        }
        try {
            $value = json_decode($request->getContent(), true, 16, JSON_THROW_ON_ERROR);
            return is_array($value) ? $value : null;
        } catch (\JsonException) {
            return null;
        }
    }

    private function cleanEnvelope(mixed $payload): ?string
    {
        if (!is_array($payload) || ($payload['v'] ?? null) !== 1 ||
            !is_string($payload['iv'] ?? null) || !is_string($payload['data'] ?? null)) {
            return null;
        }

        $iv = base64_decode($payload['iv'], true);
        $ciphertext = base64_decode($payload['data'], true);
        if ($iv === false || strlen($iv) !== 12 || $ciphertext === false ||
            strlen($ciphertext) < 16 || strlen($ciphertext) > 30000) {
            return null;
        }

        return json_encode(['v' => 1, 'iv' => $payload['iv'], 'data' => $payload['data']], JSON_THROW_ON_ERROR);
    }

    /** Fournit un CSRF actuel et l'identité de la session avant toute modification chiffrée. */
    #[Route('/csrf', name: 'app_vault_csrf', methods: ['GET'])]
    public function csrf(CsrfTokenManagerInterface $csrf): JsonResponse
    {
        return $this->respond([
            'csrfToken' => (string) $csrf->getToken('vault_api')->getValue(),
            'accountId' => $this->currentUser()->getId(),
            'accountEmail' => mb_strtolower($this->currentUser()->getEmail()),
        ]);
    }

    #[Route('/state', name: 'app_vault_state', methods: ['GET'])]
    public function state(EntityManagerInterface $em): JsonResponse
    {
        $user = $this->currentUser();
        $entries = $em->getRepository(VaultEntry::class)->findBy(['owner' => $user], ['updatedAt' => 'DESC'], 3000);

        return $this->respond([
            'initialized' => $user->getVaultSalt() !== null && $user->getVaultCheck() !== null,
            'salt' => $user->getVaultSalt(),
            'check' => $user->getVaultCheck() ? json_decode($user->getVaultCheck(), true) : null,
            'kdfVersion' => $user->getVaultKdfVersion(),
            'sharingPrivateKey' => $user->getSharingPrivateKey() ? json_decode($user->getSharingPrivateKey(), true) : null,
            'invitations' => array_map(static fn (VaultInvitation $i) => ['id'=>$i->getId(),'encryptedPrivateKey'=>json_decode($i->getEncryptedPrivateKey(),true)],
                $em->getRepository(VaultInvitation::class)->findBy(['owner'=>$user])),
            'entries' => array_map(static fn (VaultEntry $item) => [
                'id' => $item->getId(),
                'payload' => json_decode($item->getEncryptedPayload(), true),
                'createdAt' => $item->getCreatedAt()->format(DATE_ATOM),
                'updatedAt' => $item->getUpdatedAt()->format(DATE_ATOM),
            ], $entries),
        ]);
    }

    #[Route('/initialize', name: 'app_vault_initialize', methods: ['POST'])]
    public function initialize(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->verifyMutation($request)) {
            return $this->respond(['error' => 'Jeton de protection invalide.'], 403);
        }
        $body = $this->jsonBody($request);
        $salt = $body['salt'] ?? null;
        $check = $this->cleanEnvelope($body['check'] ?? null);
        $kdfVersion = $body['kdfVersion'] ?? 1;
        if (!is_string($salt) || strlen($salt) > 64 || strlen((string) base64_decode($salt, true)) !== 16 ||
            $check === null || !in_array($kdfVersion, [1, 2], true)) {
            return $this->respond(['error' => 'Initialisation invalide.'], 422);
        }
        $user = $this->currentUser();
        if ($user->getVaultSalt() !== null || $user->getVaultCheck() !== null) {
            return $this->respond(['error' => 'Le coffre est deja initialise.'], 409);
        }
        // Mise a jour atomique pour interdire deux initialisations concurrentes.
        $changed = $em->getConnection()->executeStatement(
            'UPDATE vault_user SET vault_salt = :salt, vault_check = :check, vault_kdf_version = :kdfVersion WHERE id = :id AND vault_salt IS NULL AND vault_check IS NULL',
            ['salt' => $salt, 'check' => $check, 'kdfVersion' => $kdfVersion, 'id' => $user->getId()]
        );
        if ($changed !== 1) {
            return $this->respond(['error' => 'Le coffre est deja initialise.'], 409);
        }
        return $this->respond(['ok' => true], 201);
    }

    /** Conversion des anciens coffres vers le mot de passe unique, atomique et sans decryptage serveur. */
    #[Route('/rekey', name: 'app_vault_rekey', methods: ['POST'])]
    public function rekey(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->verifyMutation($request)) return $this->respond(['error'=>'CSRF invalide.'], 403);
        $raw = $request->getContent();
        if (strlen($raw) > 10_000_000) return $this->respond(['error'=>'Taille de sauvegarde depassee.'],413);
        try { $body = json_decode($raw, true, 10, JSON_THROW_ON_ERROR); }
        catch (\Throwable) { return $this->respond(['error'=>'JSON invalide.'],422); }
        if (!is_array($body)) return $this->respond(['error'=>'Corps invalide.'],422);
        $salt=$body['salt']??null;
        $check=$this->cleanEnvelope($body['check']??null);
        $entries=$body['entries']??null;
        $sends=$body['sends']??null;
        $invitations=$body['invitations']??null;
        $sharingPrivateKey=$body['sharingPrivateKey']??null;
        $kdfVersion=$body['kdfVersion']??1;
        if (!is_string($salt) || strlen($salt)>64 || strlen((string)base64_decode($salt,true))!==16 ||
            $check===null || !is_array($entries) || !is_array($sends) || !is_array($invitations) ||
            !in_array($kdfVersion,[1,2],true) ||
            count($entries)>3000 || count($sends)>1000 || count($invitations)>500) return $this->respond(['error'=>'Conversion invalide.'],422);
        $user=$this->currentUser();
        // Inclure la cle privee de partage dans toute conversion de mot de passe.
        $currentSharingKey=$user->getSharingPrivateKey();
        $newSharingKey=$currentSharingKey===null ? null : $this->cleanEnvelope($sharingPrivateKey);
        if ($currentSharingKey!==null && $newSharingKey===null) return $this->respond(['error'=>'La cle privee de partage doit etre rechiffree.'],422);
        $id=$user->getId();
        $conn=$em->getConnection();
        $entryIds=$conn->fetchFirstColumn('SELECT id FROM vault_entry WHERE owner_id = :owner', ['owner'=>$id]);
        $sendIds=$conn->fetchFirstColumn('SELECT id FROM secure_send WHERE owner_id = :owner', ['owner'=>$id]);
        $inviteIds=$conn->fetchFirstColumn('SELECT id FROM vault_invitation WHERE owner_id = :owner', ['owner'=>$id]);
        $incomingEntries=[]; $incomingSends=[]; $incomingInvites=[];
        foreach($entries as $entry) {
            $eid=$entry['id']??null;
            $encrypted=$this->cleanEnvelope($entry['payload']??null);
            if (!is_string($eid)||isset($incomingEntries[$eid])||$encrypted===null) return $this->respond(['error'=>'Element invalide.'],422);
            $incomingEntries[$eid]=$encrypted;
        }
        foreach($sends as $send) {
            $sid=$send['id']??null;
            $payload=$this->cleanEnvelope($send['ownerPayload']??null);
            if (!is_string($sid)||isset($incomingSends[$sid])||$payload===null) return $this->respond(['error'=>'Send invalide.'],422);
            $incomingSends[$sid]=$payload;
        }
        foreach($invitations as $invite) {
            $iid=$invite['id']??null;
            $payload=$this->cleanEnvelope($invite['encryptedPrivateKey']??null);
            if(!is_string($iid)||isset($incomingInvites[$iid])||$payload===null) return $this->respond(['error'=>'Invitation invalide.'],422);
            $incomingInvites[$iid]=$payload;
        }
        $expectedE=array_map('strval',$entryIds); $expectedS=array_map('strval',$sendIds); $expectedI=array_map('strval',$inviteIds);
        sort($expectedE);sort($expectedS);sort($expectedI);
        $postedE=array_keys($incomingEntries);$postedS=array_keys($incomingSends);$postedI=array_keys($incomingInvites);
        sort($postedE);sort($postedS);sort($postedI);
        if ($expectedE!==$postedE || $expectedS!==$postedS || $expectedI!==$postedI) return $this->respond(['error'=>'Le coffre a change : actualisez avant de convertir.'],409);
        $conn->beginTransaction();
        try {
            foreach($incomingEntries as $eid=>$payload) $conn->executeStatement('UPDATE vault_entry SET encrypted_payload=:payload WHERE id=:id AND owner_id=:owner', ['payload'=>$payload,'id'=>$eid,'owner'=>$id]);
            foreach($incomingSends as $sid=>$payload) $conn->executeStatement('UPDATE secure_send SET owner_payload=:payload WHERE id=:id AND owner_id=:owner', ['payload'=>$payload,'id'=>$sid,'owner'=>$id]);
            foreach($incomingInvites as $iid=>$payload) $conn->executeStatement('UPDATE vault_invitation SET encrypted_private_key=:payload WHERE id=:id AND owner_id=:owner', ['payload'=>$payload,'id'=>$iid,'owner'=>$id]);
            if ($currentSharingKey!==null) {
                $conn->executeStatement('UPDATE vault_user SET sharing_private_key=:priv WHERE id=:id', ['priv'=>$newSharingKey,'id'=>$id]);
            }
            $conn->executeStatement('UPDATE vault_user SET vault_salt=:salt,vault_check=:check,vault_kdf_version=:kdfVersion WHERE id=:id', ['salt'=>$salt,'check'=>$check,'kdfVersion'=>$kdfVersion,'id'=>$id]);
            $conn->commit();
        } catch (\Throwable $e) { $conn->rollBack(); throw $e; }
        $user->replaceVaultMetadata($salt,$check,$kdfVersion);
        return $this->respond(['ok'=>true]);
    }

    #[Route('/entries', name: 'app_vault_entry_create', methods: ['POST'])]
    public function create(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->verifyMutation($request)) {
            return $this->respond(['error' => 'Jeton de protection invalide.'], 403);
        }
        $user = $this->currentUser();
        if ($user->getVaultSalt() === null) {
            return $this->respond(['error' => 'Initialisez le coffre.'], 409);
        }
        $body = $this->jsonBody($request);
        $envelope = $this->cleanEnvelope($body['payload'] ?? null);
        if ($envelope === null) {
            return $this->respond(['error' => 'Donnees chiffrees invalides.'], 422);
        }
        $entry = new VaultEntry(Uuid::v4()->toRfc4122(), $user, $envelope);
        $em->persist($entry);
        $em->flush();
        return $this->respond(['ok' => true, 'id' => $entry->getId(), 'updatedAt' => $entry->getUpdatedAt()->format(DATE_ATOM)], 201);
    }

    #[Route('/entries/{id}', name: 'app_vault_entry_update', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['PUT'])]
    public function update(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->verifyMutation($request)) {
            return $this->respond(['error' => 'Jeton de protection invalide.'], 403);
        }
        $entry = $em->getRepository(VaultEntry::class)->findOneBy(['id' => $id, 'owner' => $this->currentUser()]);
        if ($entry === null) {
            return $this->respond(['error' => 'Element introuvable.'], 404);
        }
        $body = $this->jsonBody($request);
        $envelope = $this->cleanEnvelope($body['payload'] ?? null);
        if ($envelope === null) {
            return $this->respond(['error' => 'Donnees chiffrees invalides.'], 422);
        }
        $entry->replacePayload($envelope);
        $em->flush();
        return $this->respond(['ok' => true, 'updatedAt' => $entry->getUpdatedAt()->format(DATE_ATOM)]);
    }

    #[Route('/entries/{id}', name: 'app_vault_entry_delete', requirements: ['id' => '[0-9a-fA-F-]{36}'], methods: ['DELETE'])]
    public function delete(string $id, Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->verifyMutation($request)) {
            return $this->respond(['error' => 'Jeton de protection invalide.'], 403);
        }
        $entry = $em->getRepository(VaultEntry::class)->findOneBy(['id' => $id, 'owner' => $this->currentUser()]);
        if ($entry === null) {
            return $this->respond(['error' => 'Element introuvable.'], 404);
        }
        $em->remove($entry);
        $em->flush();
        return $this->respond(['ok' => true]);
    }
}
