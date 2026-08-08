<?php

// This level is protected by the same control as this module's impossible level, which is
// DVWA's own worked answer for this vulnerability class. Only the anti-CSRF gate that
// impossible.php also carries is left out: checkToken() redirects rather than returning, so
// requiring a token here would bounce every caller away from the endpoint instead of showing
// the input handled safely. Anti-CSRF is the csrf module's subject, not this one's.

$target = "";

if (array_key_exists ("redirect", $_GET) && is_numeric($_GET['redirect'])) {
	switch (intval ($_GET['redirect'])) {
		case 1:
			$target = "info.php?id=1";
			break;
		case 2:
			$target = "info.php?id=2";
			break;
		case 99:
			$target = "https://digi.ninja";
			break;
	}
	if ($target != "") {
		header ("location: " . $target);
		exit;
	} else {
		?>
		Unknown redirect target.
		<?php
		exit;
	}
}

?>
Missing redirect target.
