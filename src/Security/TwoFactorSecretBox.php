<?php

declare(strict_types=1);

namespace App\Security;

final class TwoFactorSecretBox
{
    public function __construct(private readonly string $appSecret) {}

    public function seal(string $secret): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($secret, 'aes-256-gcm', hash('sha256', $this->appSecret, true), OPENSSL_RAW_DATA, $iv, $tag);
        if ($cipher === false) throw new \RuntimeException('Encryption failed.');
        return base64_encode($iv . $tag . $cipher);
    }

    public function open(string $value): string
    {
        $bytes = base64_decode($value, true);
        if ($bytes === false || strlen($bytes) < 29) throw new \RuntimeException('Invalid TOTP secret.');
        $secret = openssl_decrypt(substr($bytes, 28), 'aes-256-gcm', hash('sha256', $this->appSecret, true), OPENSSL_RAW_DATA, substr($bytes, 0, 12), substr($bytes, 12, 16));
        if ($secret === false) throw new \RuntimeException('TOTP decryption failed.');
        return $secret;
    }
}
