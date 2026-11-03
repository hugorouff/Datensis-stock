<?php
require __DIR__ . '/../src/Security/Totp.php';
require __DIR__ . '/../src/Security/TwoFactorSecretBox.php';
use App\Security\Totp;
use App\Security\TwoFactorSecretBox;
$secret = Totp::generateSecret();
assert(strlen($secret) === 32 && preg_match('/^[A-Z2-7]{32}$/', $secret));
// RFC 6238 SHA1 59s: 8 digits 94287082, 6 derniers chiffres 287082.
assert(Totp::code('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1) === '287082');
$step = intdiv(time(), 30);
$code = Totp::code($secret, $step);
assert(Totp::verify($secret, $code) === $step);
assert(Totp::verify($secret, $code, $step) === null);
$box = new TwoFactorSecretBox('test-secret-change-me');
assert($box->open($box->seal($secret)) === $secret);
echo "OK TOTP RFC, protection contre rejeu, secret chiffre\n";
