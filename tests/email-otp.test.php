<?php
require __DIR__ . '/../src/Security/EmailOtpCode.php';
use App\Security\EmailOtpCode;
$issued = EmailOtpCode::issue('id-a', 1000);
assert(preg_match('/^[0-9]{6}$/D', $issued['code']) === 1);
assert(!isset($issued['challenge']['code']));
assert(EmailOtpCode::matches($issued['challenge'], 'id-a', $issued['code'], 1100));
assert(!EmailOtpCode::matches($issued['challenge'], 'id-b', $issued['code'], 1100));
assert(!EmailOtpCode::matches($issued['challenge'], 'id-a', $issued['code'], 1301));
assert(!EmailOtpCode::matches($issued['challenge'], 'id-a', 'abcdef', 1100));
echo "OK Email OTP: format, code hache, utilisateur et expiration\n";
