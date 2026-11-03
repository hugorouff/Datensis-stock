<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

final class EmailOtpSender
{
    public function __construct(
        private readonly MailerInterface $mailer,
        private readonly string $brevoDsn,
        private readonly string $from,
    ) {}

    public function send(string $recipient, string $code): void
    {
        // Ne jamais accorder l'acces si le transport est null://null (aucun envoi reel).
        if (!str_starts_with($this->brevoDsn, 'brevo+api://') || !filter_var($this->from, FILTER_VALIDATE_EMAIL)) {
            throw new \RuntimeException('Brevo non configure. Definir MAILER_DSN et MAILER_FROM dans .env.local.');
        }
        $email = (new Email())
            ->from($this->from)
            ->to($recipient)
            ->subject('Datensis Stock - Votre code de verification')
            ->text("Votre code de verification Datensis Stock est : {$code}\n\nCe code expire dans 5 minutes.\nSi vous n'avez pas demande de code, ignorez ce message.\nNe communiquez jamais ce code.");
        $this->mailer->send($email);
    }
}
