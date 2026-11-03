<?php

declare(strict_types=1);

namespace App\Security;

/** RFC 6238 / RFC 4226, SHA-1, 30s, 6 digits (compatible authenticator apps). */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(): string
    {
        // 160 bits aleatoires, encodes sans perte en 32 caracteres Base32.
        $data = random_bytes(20);
        $out = '';
        $bits = 0;
        $value = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $value = ($value << 8) | ord($data[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::ALPHABET[($value >> $bits) & 31];
            }
            $value &= (1 << $bits) - 1;
        }
        return $out;
    }

    public static function code(string $secret, int $counter): ?string
    {
        $bin = self::decode($secret);
        if ($bin === null || $counter < 0) return null;
        $packed = pack('N2', ($counter >> 32) & 0xffffffff, $counter & 0xffffffff);
        $hash = hash_hmac('sha1', $packed, $bin, true);
        $offset = ord($hash[19]) & 15;
        $number = ((ord($hash[$offset]) & 127) << 24) |
            (ord($hash[$offset + 1]) << 16) |
            (ord($hash[$offset + 2]) << 8) |
            ord($hash[$offset + 3]);
        return str_pad((string) ($number % 1000000), 6, '0', STR_PAD_LEFT);
    }

    public static function verify(string $secret, string $code, int $lastStep = -1): ?int
    {
        if (!preg_match('/^\d{6}$/D', $code)) return null;
        $step = intdiv(time(), 30);
        foreach ([$step, $step - 1, $step + 1] as $i) {
            if ($i <= $lastStep) continue;
            $expected = self::code($secret, $i);
            if ($expected !== null && hash_equals($expected, $code)) return $i;
        }
        return null;
    }

    private static function decode(string $input): ?string
    {
        $bits = 0; $value = 0; $out = '';
        $input = strtoupper(str_replace(' ', '', $input));
        if (!preg_match('/^[A-Z2-7]{16,64}$/D', $input)) return null;
        foreach (str_split($input) as $char) {
            $v = strpos(self::ALPHABET, $char);
            if ($v === false) return null;
            $value = ($value << 5) | $v;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($value >> $bits) & 255);
                $value &= (1 << $bits) - 1;
            }
        }
        return $out;
    }
}
