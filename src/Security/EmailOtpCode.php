<?php

declare(strict_types=1);

namespace App\Security;

/** Challenge uniquement dans la session serveur; jamais le code en clair. */
final class EmailOtpCode
{
    public static function issue(string $userId, int $now): array
    {
        $code = sprintf('%06d', random_int(0, 999999));
        return [
            'code' => $code,
            'challenge' => [
                'user' => $userId,
                'hash' => password_hash($code, PASSWORD_DEFAULT),
                'expires' => $now + 300,
                'sentAt' => $now,
                'attempts' => 0,
            ],
        ];
    }

    public static function matches(array $challenge, string $userId, string $code, int $now): bool
    {
        return ($challenge['user'] ?? null) === $userId
            && is_int($challenge['expires'] ?? null)
            && $now <= $challenge['expires']
            && preg_match('/^[0-9]{6}$/D', $code) === 1
            && password_verify($code, (string) ($challenge['hash'] ?? ''));
    }
}
