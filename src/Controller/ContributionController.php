<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\VaultInvitation;
use App\Entity\VaultContribution;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

#[Route('/contribute/{token}', requirements:['token'=>'[A-Za-z0-9_-]{43}'])]
final class ContributionController extends AbstractController
{
    public function __construct(
        #[Autowire('%env(APP_SECRET)%')] private readonly string $secret,
        #[Autowire('%env(MAILER_DSN)%')] private readonly string $mailerDsn,
        #[Autowire('%env(default:app.default_mailer_from:MAILER_FROM)%')] private readonly string $mailerFrom,
    ) {}

    private function secure(Request $request): bool
    {
        return $request->isSecure() || in_array($request->getHost(), ['localhost','127.0.0.1'], true);
    }
    private function invite(string $token, EntityManagerInterface $em): ?VaultInvitation
    {
        return $em->getRepository(VaultInvitation::class)->findOneBy(['tokenHash'=>hash('sha256',$token)]);
    }
    private function out(array $data,int $status=200): JsonResponse
    {
        return (new JsonResponse($data,$status))->setPrivate();
    }
    private function csrf(Request $r): bool { return $this->isCsrfTokenValid('ds_contribute', (string)$r->headers->get('X-CSRF-Token')); }
    private function otpHash(VaultInvitation $i,string $code): string { return hash_hmac('sha256',$i->getId().':'.$code,$this->secret); }
    private function sessionHash(Request $r): string { return hash_hmac('sha256',$r->getSession()->getId(),$this->secret); }

    #[Route('',name:'ds_contribute_page',methods:['GET'])]
    public function page(string $token,Request $r,EntityManagerInterface $em): Response
    {
        if (!$this->secure($r)) throw $this->createAccessDeniedException('HTTPS obligatoire.');
        $i=$this->invite($token,$em);
        if (!$i||!$i->isUsable()) throw $this->createNotFoundException('Lien expiré, utilisé ou révoqué.');
        return $this->render('contribute/index.html.twig',[
            'recipient'=>$i->getRecipientEmail(),
            'folder'=>$i->getCompanyFolder(),
            'public_key'=>$i->getPublicKey(),
        ]);
    }

    #[Route('/consent',name:'ds_contribute_consent',methods:['POST'])]
    public function consent(string $token,Request $r,EntityManagerInterface $em,MailerInterface $mailer,
        #[Autowire(service:'limiter.ds_invite_email')] RateLimiterFactory $limiter): JsonResponse
    {
        if (!$this->secure($r)) return $this->out(['error'=>'HTTPS obligatoire.'],403);
        if (!$this->csrf($r)) return $this->out(['error'=>'Protection CSRF invalide.'],403);
        $i=$this->invite($token,$em);
        if (!$i||!$i->isUsable()) return $this->out(['error'=>'Invitation indisponible.'],410);
        $b=json_decode($r->getContent(),true);
        if (!is_array($b) || ($b['consent']??null)!==true) return $this->out(['error'=>'Le consentement explicite est requis.'],422);
        $limit=$limiter->create($i->getId());
        if (!$limit->consume(1)->isAccepted()) return $this->out(['error'=>'Trop de demandes de code. Réessayez plus tard.'],429);
        // Fail closed: never generate an OTP which cannot be delivered to the recipient.
        if (!str_starts_with($this->mailerDsn,'brevo+api://') || !filter_var($this->mailerFrom,FILTER_VALIDATE_EMAIL))
            return $this->out(['error'=>'Messagerie de verification non configuree.'],503);
        $code=(string)random_int(100000,999999);
        try {
            $mailer->send((new Email())->from($this->mailerFrom)->to($i->getRecipientEmail())
                ->subject('Datensis Stock - Code de depot individuel')
                ->text("Vous avez consenti a un depot Datensis Stock.\nCode : {$code}\nExpiration : 10 minutes.\nSi ce n'est pas vous, ignorez ce message.\nNe communiquez pas ce code."));
        } catch (\Throwable) { return $this->out(['error'=>'Envoi du code impossible. Contactez l’expéditeur.'],503); }
        $i->markConsent();
        $i->issueOtp($this->otpHash($i,$code),$this->sessionHash($r));
        $em->flush();
        return $this->out(['ok'=>true,'message'=>'Un code a été envoyé à l’adresse du destinataire prévu.']);
    }

    #[Route('/verify',name:'ds_contribute_verify',methods:['POST'])]
    public function verify(string $token,Request $r,EntityManagerInterface $em,
        #[Autowire(service:'limiter.ds_invite_verify')] RateLimiterFactory $limiter): JsonResponse
    {
        if (!$this->secure($r)) return $this->out(['error'=>'HTTPS obligatoire.'],403);
        if (!$this->csrf($r)) return $this->out(['error'=>'CSRF invalide.'],403);
        $i=$this->invite($token,$em);
        if (!$i||!$i->isUsable()||!$i->getConsentedAt()) return $this->out(['error'=>'Invitation indisponible.'],410);
        if (!$limiter->create($i->getId())->consume(1)->isAccepted()) return $this->out(['error'=>'Trop de tentatives.'],429);
        $body=json_decode($r->getContent(),true);
        $code=is_array($body)?($body['code']??null):null;
        if (!is_string($code)||!preg_match('/^\d{6}$/D',$code)) return $this->out(['error'=>'Code incorrect.'],422);
        $valid=$i->verifyOtp($this->otpHash($i,$code),$this->sessionHash($r));
        $em->flush();
        if (!$valid) return $this->out(['error'=>'Code incorrect, expiré ou session différente.'],403);
        $r->getSession()->migrate(true);
        $r->getSession()->set('ds_invite_verified_'.$i->getId(),true);
        return $this->out(['ok'=>true]);
    }

    #[Route('/submit',name:'ds_contribute_submit',methods:['POST'])]
    public function submit(string $token,Request $r,EntityManagerInterface $em): JsonResponse
    {
        if (!$this->secure($r)) return $this->out(['error'=>'HTTPS obligatoire.'],403);
        if (!$this->csrf($r)) return $this->out(['error'=>'CSRF invalide.'],403);
        $i=$this->invite($token,$em);
        if (!$i||!$i->isUsable()) return $this->out(['error'=>'Lien expiré ou déjà utilisé.'],410);
        if ($r->getSession()->get('ds_invite_verified_'.$i->getId()) !== true) return $this->out(['error'=>'Vérification e-mail obligatoire.'],403);
        if (strlen($r->getContent())>120000) return $this->out(['error'=>'Dépôt trop volumineux.'],413);
        $b=json_decode($r->getContent(),true);
        $payload=is_array($b)?($b['payload']??null):null;
        if (!is_array($payload)||($payload['v']??null)!==1||!is_string($payload['iv']??null)||
            !is_string($payload['data']??null)||!is_string($payload['wrappedKey']??null)) return $this->out(['error'=>'Dépôt chiffré invalide.'],422);
        $iv=base64_decode($payload['iv'],true);$data=base64_decode($payload['data'],true);$wrapped=base64_decode($payload['wrappedKey'],true);
        if ($iv===false||strlen($iv)!==12||$data===false||strlen($data)<16||strlen($data)>80000||$wrapped===false||strlen($wrapped)!==256) return $this->out(['error'=>'Enveloppe chiffrée invalide.'],422);
        $ciphertext=json_encode(['v'=>1,'iv'=>$payload['iv'],'data'=>$payload['data'],'wrappedKey'=>$payload['wrappedKey']],JSON_THROW_ON_ERROR);
        $conn=$em->getConnection();$conn->beginTransaction();
        try {
            // One-time redemption, atomic: a second browser/session cannot reuse this invite.
            $changed=$conn->executeStatement('UPDATE vault_invitation SET redeemed_at = :now WHERE id = :id AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > :now',
                ['now'=>(new \DateTimeImmutable('now',new \DateTimeZone('UTC')))->format('Y-m-d H:i:s'),'id'=>$i->getId()]);
            if ($changed!==1) { $conn->rollBack(); return $this->out(['error'=>'Lien déjà utilisé.'],410); }
            $conn->insert('vault_contribution',[
                'id'=>Uuid::v4()->toRfc4122(),'invitation_id'=>$i->getId(),'ciphertext'=>$ciphertext,
                'created_at'=>(new \DateTimeImmutable('now',new \DateTimeZone('UTC')))->format('Y-m-d H:i:s'), 'imported_at'=>null,
            ]);
            $conn->commit();
        } catch (\Throwable) { $conn->rollBack(); return $this->out(['error'=>'Dépôt non enregistré.'],500); }
        $r->getSession()->remove('ds_invite_verified_'.$i->getId());
        return $this->out(['ok'=>true,'message'=>'Dépôt chiffré reçu. Le lien ne peut plus être utilisé.'],201);
    }
}
