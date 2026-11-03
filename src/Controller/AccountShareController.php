<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Security\EmailOtpSender;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

#[Route('/api/shares')]
final class AccountShareController extends AbstractController
{
    public function __construct(#[Autowire('%env(APP_SECRET)%')] private readonly string $secret) {}

    private function me(): User
    {
        $user = $this->getUser();
        if (!$user instanceof User) throw $this->createAccessDeniedException();
        return $user;
    }

    private function out(array $data, int $status = 200): JsonResponse
    {
        $r = new JsonResponse($data, $status);
        $r->headers->set('Cache-Control', 'no-store, private');
        $r->headers->set('X-Content-Type-Options', 'nosniff');
        return $r;
    }

    private function input(Request $request): ?array
    {
        if (strlen($request->getContent()) > 300000) return null;
        try { $value = json_decode($request->getContent(), true, 10, JSON_THROW_ON_ERROR); }
        catch (\JsonException) { return null; }
        return is_array($value) ? $value : null;
    }

    private function csrf(Request $request): bool
    {
        return $this->isCsrfTokenValid('vault_api', (string) $request->headers->get('X-CSRF-Token', ''));
    }

    private function envelope(mixed $value): ?string
    {
        if (!is_array($value) || ($value['v'] ?? null) !== 1 || !is_string($value['iv'] ?? null) || !is_string($value['data'] ?? null)) return null;
        $iv = base64_decode($value['iv'], true);
        $cipher = base64_decode($value['data'], true);
        if ($iv === false || strlen($iv) !== 12 || $cipher === false || strlen($cipher) < 16 || strlen($cipher) > 200000) return null;
        return json_encode(['v'=>1,'iv'=>$value['iv'],'data'=>$value['data']], JSON_THROW_ON_ERROR);
    }

    private function sealed(mixed $value): ?string
    {
        if (!is_array($value) || !is_string($value['wrappedKey'] ?? null)) return null;
        $cipher = $this->envelope($value);
        $wrapped = base64_decode($value['wrappedKey'], true);
        if ($cipher === null || $wrapped === false || strlen($wrapped) !== 384) return null;
        return json_encode(['v'=>1,'iv'=>$value['iv'],'data'=>$value['data'],'wrappedKey'=>$value['wrappedKey']], JSON_THROW_ON_ERROR);
    }

    private function now(): string { return gmdate('Y-m-d H:i:s'); }

    #[Route('/identity', name:'ds_shares_identity', methods:['GET'])]
    public function identity(): JsonResponse
    {
        $me=$this->me();
        return $this->out([
            'verified' => true,
            'publicKey' => $me->getSharingPublicKey(),
            'encryptedPrivateKey' => $me->getSharingPrivateKey() === null ? null : json_decode($me->getSharingPrivateKey(), true),
            'email' => $me->getEmail(),
        ]);
    }

    #[Route('/identity', name:'ds_shares_register_keys', methods:['POST'])]
    public function registerKeys(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $me=$this->me();
        if (!$me->getVaultSalt()) return $this->out(['error'=>'Déverrouillez et initialisez votre coffre.'],409);
        if ($me->getSharingPublicKey() !== null) return $this->out(['error'=>'La paire de clés existe déjà.'],409);
        $b=$this->input($request);
        $key=is_array($b)?($b['publicKey']??null):null;
        $private=$this->envelope($b['encryptedPrivateKey']??null);
        if (!is_string($key) || strlen($key)>8192 || $private===null) return $this->out(['error'=>'Clés de partage invalides.'],422);
        $der=base64_decode($key,true);
        if ($der===false || strlen($der)<350 || strlen($der)>1000) return $this->out(['error'=>'Clé publique invalide.'],422);
        $pem="-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der),64,"\n")."-----END PUBLIC KEY-----\n";
        $parsed=openssl_pkey_get_public($pem);
        $details=$parsed===false?false:openssl_pkey_get_details($parsed);
        if (!is_array($details) || ($details['type']??null)!==OPENSSL_KEYTYPE_RSA || ($details['bits']??0)!==3072) return $this->out(['error'=>'Clé RSA 3072 invalide.'],422);
        // Empêcher l'écrasement de clés : autrement les anciens accès seraient illisibles.
        $changed=$em->getConnection()->executeStatement('UPDATE vault_user SET sharing_public_key=:pub, sharing_private_key=:priv WHERE id=:id AND sharing_public_key IS NULL AND sharing_private_key IS NULL',
            ['pub'=>$key,'priv'=>$private,'id'=>$me->getId()]);
        if ($changed!==1) return $this->out(['error'=>'Clé déjà enregistrée.'],409);
        return $this->out(['ok'=>true],201);
    }

    #[Route('/verify-email/start', name:'ds_shares_verify_email_start', methods:['POST'])]
    public function startVerify(Request $request, EmailOtpSender $sender,
        #[Autowire(service:'limiter.ds_share_email')] RateLimiterFactory $limiter): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $me=$this->me();
        if ($me->getSharingEmailVerifiedAt()) return $this->out(['ok'=>true]);
        if (!$limiter->create($me->getId())->consume(1)->isAccepted()) return $this->out(['error'=>'Trop de demandes. Réessayez plus tard.'],429);
        $code=(string)random_int(100000,999999);
        try { $sender->send($me->getEmail(),$code); }
        catch (\Throwable) { return $this->out(['error'=>'Envoi impossible : configurez Brevo (MAILER_DSN et MAILER_FROM).'],503); }
        $request->getSession()->set('ds_share_email_verify', [
            'hash'=>hash_hmac('sha256',$me->getId().':'.$code,$this->secret),
            'expires'=>time()+300, 'attempts'=>0,
        ]);
        return $this->out(['ok'=>true,'message'=>'Code envoyé à votre adresse de connexion.']);
    }

    #[Route('/verify-email/confirm', name:'ds_shares_verify_email_confirm', methods:['POST'])]
    public function confirmVerify(Request $request, EntityManagerInterface $em,
        #[Autowire(service:'limiter.ds_share_verify')] RateLimiterFactory $limiter): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $me=$this->me();
        if (!$limiter->create($me->getId())->consume(1)->isAccepted()) return $this->out(['error'=>'Trop de tentatives.'],429);
        $b=$this->input($request);$code=is_array($b)?($b['code']??null):null;
        $record=$request->getSession()->get('ds_share_email_verify');
        if (!is_string($code)||!preg_match('/^\d{6}$/D',$code)||!is_array($record)||($record['expires']??0)<time()||($record['attempts']??0)>=5) return $this->out(['error'=>'Code invalide ou expiré.'],403);
        $record['attempts']++;
        $request->getSession()->set('ds_share_email_verify',$record);
        if (!hash_equals((string)$record['hash'],hash_hmac('sha256',$me->getId().':'.$code,$this->secret))) return $this->out(['error'=>'Code invalide ou expiré.'],403);
        $me->verifySharingEmail();$em->flush();
        $request->getSession()->remove('ds_share_email_verify');
        return $this->out(['ok'=>true]);
    }

    // Suggestions limitees aux comptes eligibles au partage. Pas d'annuaire public.
    #[Route('/recipients', name:'ds_shares_recipients_search', methods:['GET'])]
    public function searchRecipients(Request $request, EntityManagerInterface $em,
        #[Autowire(service:'limiter.ds_share_suggest')] RateLimiterFactory $limiter): JsonResponse
    {
        $me = $this->me();
        $query = strtolower(trim((string) $request->query->get('q', '')));
        if (strlen($query) < 3 || strlen($query) > 64 || !preg_match('/^[a-z0-9._%+@\-]+$/D', $query)) {
            return $this->out(['results' => []]);
        }
        if (!$limiter->create($me->getId())->consume(1)->isAccepted()) {
            return $this->out(['error' => 'Trop de recherches. Patientez avant de recommencer.'], 429);
        }
        // '%' et '_' doivent etre pris litteralement et non comme jokers SQL.
        $pattern = '%' . str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $query) . '%';
        $emails = $em->getConnection()->fetchFirstColumn(
            "SELECT email FROM vault_user
             WHERE id <> :owner
               AND disabled_at IS NULL
               AND roles NOT LIKE '%ROLE_ADMIN%'
               AND LOWER(email) LIKE :query ESCAPE '!'
             ORDER BY email ASC LIMIT 10",
            ['owner' => $me->getId(), 'query' => $pattern]
        );
        return $this->out(['results' => array_values(array_map('strval', $emails))]);
    }

    #[Route('/recipient', name:'ds_shares_recipient', methods:['POST'])]
    public function recipient(Request $request, EntityManagerInterface $em,
        #[Autowire(service:'limiter.ds_share_lookup')] RateLimiterFactory $limiter): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $me=$this->me();
        
        if (!$limiter->create($me->getId())->consume(1)->isAccepted()) return $this->out(['error'=>'Trop de recherches.'],429);
        $b=$this->input($request);
        $email=is_array($b)?strtolower(trim((string)($b['email']??''))):'';
        if (strlen($email)>180||!filter_var($email,FILTER_VALIDATE_EMAIL)||$email===$me->getEmail()) return $this->out(['error'=>'Adresse destinataire invalide.'],422);
        $to=$em->getRepository(User::class)->findOneBy(['email'=>$email]);
        if (!$to instanceof User || $to->isDisabled() || in_array('ROLE_ADMIN', $to->getRoles(), true)) {
            return $this->out(['error'=>'Compte utilisateur introuvable ou suspendu.'],404);
        }
        // Un compte nouvellement cree est selectionnable immediatement : le partage
        // sera chiffre lorsque le destinataire aura ouvert une fois son coffre.
        return $this->out(['email'=>$to->getEmail(),'publicKey'=>$to->getSharingPublicKey(),
            'pending'=>!$to->getSharingPublicKey()]);
    }

    #[Route('',name:'ds_shares_list', methods:['GET'])]
    public function listing(EntityManagerInterface $em): JsonResponse
    {
        $me=$this->me();$conn=$em->getConnection();
        $out=$conn->fetchAllAssociative('SELECT s.id,s.scope_type,s.owner_metadata,s.encrypted_bundle,s.created_at,s.updated_at,s.accepted_at,s.declined_at,s.revoked_at,u.email AS recipient_email,u.sharing_public_key AS recipient_public_key FROM vault_share s JOIN vault_user u ON u.id=s.recipient_id WHERE s.owner_id=:uid ORDER BY s.created_at DESC LIMIT 500', ['uid'=>$me->getId()]);
        // Garder aussi les partages en cours de preparation : sinon le destinataire
        // voit « Aucune demande » alors qu'un partage existe bien en base.
        // Le contenu chiffre n'est transmis qu'apres acceptation explicite.
        $incoming=$conn->fetchAllAssociative('SELECT s.id,s.scope_type,s.encrypted_bundle,s.created_at,s.updated_at,s.accepted_at,s.declined_at,s.revoked_at,u.email AS owner_email FROM vault_share s JOIN vault_user u ON u.id=s.owner_id WHERE s.recipient_id=:uid AND s.revoked_at IS NULL AND s.declined_at IS NULL ORDER BY s.created_at DESC LIMIT 500', ['uid'=>$me->getId()]);
        return $this->out([
            'accountEmail'=>$me->getEmail(),
            'outgoing'=>array_map(fn(array $s)=>[
                'id'=>$s['id'],'scope'=>$s['scope_type'],'ownerMetadata'=>json_decode($s['owner_metadata'],true),
                'recipientEmail'=>$s['recipient_email'],'recipientPublicKey'=>$s['recipient_public_key'],
                'createdAt'=>$s['created_at'],'updatedAt'=>$s['updated_at'],'accepted'=>($s['accepted_at']!==null),
                'declined'=>($s['declined_at']!==null),'revoked'=>($s['revoked_at']!==null),
                'pendingEncryption'=>$this->sealed(json_decode((string) $s['encrypted_bundle'],true))===null,
            ],$out),
            'incoming'=>array_map(function (array $s): array {
                $encrypted=json_decode((string) $s['encrypted_bundle'],true);
                $ready=$this->sealed($encrypted)!==null;
                return [
                    'id'=>$s['id'],'scope'=>$s['scope_type'],
                    // Aucun contenu avant le consentement, et jamais de faux partage pret.
                    'encryptedBundle'=>$ready && $s['accepted_at']!==null ? $encrypted : null,
                    'ownerEmail'=>$s['owner_email'],'createdAt'=>$s['created_at'],'updatedAt'=>$s['updated_at'],
                    'accepted'=>$s['accepted_at']!==null,
                    'pendingEncryption'=>!$ready,
                ];
            },$incoming),
        ]);
    }

    #[Route('',name:'ds_shares_create',methods:['POST'])]
    public function create(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $me=$this->me();
        if (!$me->getSharingPublicKey()) return $this->out(['error'=>'Initialisez vos clés de partage.'],403);
        $b=$this->input($request);
        $email=is_array($b)?strtolower(trim((string)($b['recipientEmail']??''))):'';
        $scope=$b['scope']??null;
        if (!in_array($scope,['entry','folder'],true)||strlen($email)>180||!filter_var($email,FILTER_VALIDATE_EMAIL)||$email===$me->getEmail()) return $this->out(['error'=>'Partage invalide.'],422);
        $to=$em->getRepository(User::class)->findOneBy(['email'=>$email]);
        if (!$to instanceof User || $to->isDisabled() || in_array('ROLE_ADMIN', $to->getRoles(), true)) {
            return $this->out(['error'=>'Destinataire non disponible.'],404);
        }
        $metadata=$this->envelope($b['ownerMetadata']??null);
        // Si le destinataire n'a pas encore ouvert son coffre, on conserve UNIQUEMENT
        // la reference chiffree du proprietaire, jamais les mots de passe ni une cle privee.
        // L'emetteur finalisera le partage dans son navigateur apres activation du compte.
        $pending=$to->getSharingPublicKey()===null;
        if ($pending && ($b['pending']??false)!==true) return $this->out(['error'=>'Le destinataire doit se connecter une premiere fois.'],409);
        $bundle=$pending ? '{}' : $this->sealed($b['encryptedBundle']??null);
        if ($metadata===null||$bundle===null||strlen($metadata)>12000||strlen($bundle)>240000) return $this->out(['error'=>'Contenu chiffré invalide.'],422);
        // Aucune donnée de dossier ni mot de passe en clair n'est reçue côté serveur.
        $conn=$em->getConnection();
        $num=(int)$conn->fetchOne('SELECT COUNT(*) FROM vault_share WHERE owner_id=:id AND revoked_at IS NULL AND declined_at IS NULL',['id'=>$me->getId()]);
        if ($num>=500) return $this->out(['error'=>'Limite de partages atteinte.'],409);
        $id=Uuid::v4()->toRfc4122();$now=$this->now();
        $conn->insert('vault_share',[
            'id'=>$id,'owner_id'=>$me->getId(),'recipient_id'=>$to->getId(),'scope_type'=>$scope,
            'owner_metadata'=>$metadata,'encrypted_bundle'=>$bundle,
            'created_at'=>$now,'updated_at'=>$now,'accepted_at'=>null,'consent_version'=>null,'declined_at'=>null,'revoked_at'=>null,
        ]);
        return $this->out(['id'=>$id,'ok'=>true,'pending'=>$pending],201);
    }

    #[Route('/{id}/content',name:'ds_shares_update_content',requirements:['id'=>'[0-9a-fA-F-]{36}'],methods:['PUT'])]
    public function update(string $id,Request $request,EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $b=$this->input($request);
        $bundle=$this->sealed($b['encryptedBundle']??null);
        if ($bundle===null||strlen($bundle)>240000) return $this->out(['error'=>'Chiffrement invalide.'],422);
        $changed=$em->getConnection()->executeStatement('UPDATE vault_share SET encrypted_bundle=:bundle,updated_at=:at WHERE id=:id AND owner_id=:uid AND revoked_at IS NULL AND declined_at IS NULL',
            ['bundle'=>$bundle,'at'=>$this->now(),'id'=>$id,'uid'=>$this->me()->getId()]);
        return $changed===1?$this->out(['ok'=>true]):$this->out(['error'=>'Partage non modifiable.'],404);
    }

    #[Route('/{id}/accept',name:'ds_shares_accept',requirements:['id'=>'[0-9a-fA-F-]{36}'],methods:['POST'])]
    public function accept(string $id,Request $request,EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        if (($this->input($request)['consent']??false)!==true || ($this->input($request)['consentVersion']??'')!=='2026-10-29-v1') return $this->out(['error'=>'Consentement explicite requis.'],422);
        $me=$this->me();
        
        $conn=$em->getConnection();
        $stored=$conn->fetchOne('SELECT encrypted_bundle FROM vault_share WHERE id=:id AND recipient_id=:uid AND accepted_at IS NULL AND revoked_at IS NULL AND declined_at IS NULL',
            ['id'=>$id,'uid'=>$me->getId()]);
        if (!is_string($stored) || $this->sealed(json_decode($stored,true))===null) {
            return $this->out(['error'=>'Le partage est encore en cours de preparation.'],409);
        }
        $changed=$conn->executeStatement('UPDATE vault_share SET accepted_at=:at,consent_version=:version WHERE id=:id AND recipient_id=:uid AND accepted_at IS NULL AND revoked_at IS NULL AND declined_at IS NULL AND encrypted_bundle=:stored',
            ['at'=>$this->now(),'version'=>'2026-10-29-v1','id'=>$id,'uid'=>$me->getId(),'stored'=>$stored]);
        return $changed===1?$this->out(['ok'=>true]):$this->out(['error'=>'Partage indisponible.'],409);
    }

    #[Route('/{id}/decline',name:'ds_shares_decline',requirements:['id'=>'[0-9a-fA-F-]{36}'],methods:['POST'])]
    public function decline(string $id,Request $request,EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $changed=$em->getConnection()->executeStatement('UPDATE vault_share SET declined_at=:at,encrypted_bundle=:empty WHERE id=:id AND recipient_id=:uid AND declined_at IS NULL AND revoked_at IS NULL',
            ['at'=>$this->now(),'empty'=>'{}','id'=>$id,'uid'=>$this->me()->getId()]);
        return $changed===1?$this->out(['ok'=>true]):$this->out(['error'=>'Partage indisponible.'],404);
    }

    #[Route('/{id}/revoke',name:'ds_shares_revoke',requirements:['id'=>'[0-9a-fA-F-]{36}'],methods:['POST'])]
    public function revoke(string $id,Request $request,EntityManagerInterface $em): JsonResponse
    {
        if (!$this->csrf($request)) return $this->out(['error'=>'CSRF invalide.'],403);
        $changed=$em->getConnection()->executeStatement('UPDATE vault_share SET revoked_at=:at,encrypted_bundle=:empty WHERE id=:id AND owner_id=:uid AND revoked_at IS NULL',
            ['at'=>$this->now(),'empty'=>'{}','id'=>$id,'uid'=>$this->me()->getId()]);
        return $changed===1?$this->out(['ok'=>true]):$this->out(['error'=>'Partage indisponible.'],404);
    }
}
