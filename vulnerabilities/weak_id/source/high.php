<?php

// This level issues session IDs from a CSPRNG, the same control this module's impossible level
// uses. The previous values were an incrementing counter, the current time, or md5() of a
// counter -- all of which let anyone holding one session ID work out the ones issued before and
// after it, which is the whole weakness this module is about. 20 random bytes cannot be walked
// or predicted from a sample.
//
// One departure from impossible.php: the Secure attribute is set only when the request actually
// arrived over HTTPS. Secure is the right flag on an HTTPS deployment, but a compliant client
// never sends a Secure cookie back over plain HTTP, so hardcoding it where the app is served
// over HTTP does not harden the session -- it stops the session working at all, while looking
// like a control. HttpOnly and SameSite apply either way, and the domain is left unset so the
// cookie stays host-only rather than being widened to whatever the Host header claimed.

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$cookie_value = bin2hex(random_bytes(20));
	$secure = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off');

	setcookie("dvwaSession", $cookie_value, [
		'expires'  => time() + 3600,
		'path'     => '/vulnerabilities/weak_id/',
		'secure'   => $secure,
		'httponly' => true,
		'samesite' => 'Strict',
	]);
}
?>
