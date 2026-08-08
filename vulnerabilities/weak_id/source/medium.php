<?php

// This level is protected by the same control as this module's impossible level, which is
// DVWA's own worked answer for this vulnerability class. Only the anti-CSRF gate that
// impossible.php also carries is left out: checkToken() redirects rather than returning, so
// requiring a token here would bounce every caller away from the endpoint instead of showing
// the input handled safely. Anti-CSRF is the csrf module's subject, not this one's.

$html = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	$cookie_value = bin2hex(random_bytes(20));
	setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], true, true);
}
?>
