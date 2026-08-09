<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'Vulnerability: JavaScript Attacks' . $page[ 'title_separator' ].$page[ 'title' ];
$page[ 'page_id' ] = 'javascript';
$page[ 'help_button' ]   = 'javascript';
$page[ 'source_button' ] = 'javascript';

dvwaDatabaseConnect();

$vulnerabilityFile = '';
switch( dvwaSecurityLevelGet() ) {
	case 'low':
		$vulnerabilityFile = 'low.php';
		break;
	case 'medium':
		$vulnerabilityFile = 'medium.php';
		break;
	case 'high':
		$vulnerabilityFile = 'high.php';
		break;
	default:
		$vulnerabilityFile = 'impossible.php';
		break;
}

// The phrase the form offers. The server issues a token for this value and no other.
$default_phrase = "ChangeMe";

// A per-session secret that never leaves the server. Without it the token below cannot be
// computed, only received.
if (!array_key_exists ("javascript_secret", $_SESSION)) {
	$_SESSION['javascript_secret'] = bin2hex (random_bytes (16));
}

// The token binds a *specific phrase* to the server's authorisation of it, keyed by a secret the
// client never sees.
//
// What was here before recomputed a fixed function of the submitted phrase --
// md5(str_rot13(...)), a reversed string, a doubled SHA-256 -- and compared it to what the caller
// sent. Every one of those is derivable from data the client already holds, using an algorithm
// the page itself ships to the browser, so the token proved only that the sender could read the
// source. Obfuscating the algorithm changes nothing: it is still being executed on the
// attacker's machine.
//
// Note that a session-wide token would not fix this either. Any client that loads the page is
// handed one, so it would authorise *any* phrase the holder cared to submit. What matters is
// that the token commits to the phrase, so the only phrase that can be submitted is the one the
// server chose to authorise.
function phrase_token ($phrase) {
	return hash_hmac ('sha256', $phrase, $_SESSION['javascript_secret']);
}

$message = "";
// Check what was sent in to see if it was what was expected. The level's own `token` field is
// left in place so each level's script still demonstrates the point; the server simply no longer
// treats it as authority.
if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (array_key_exists ("phrase", $_POST) && array_key_exists ("user_token", $_POST)) {

		$phrase = $_POST['phrase'];
		$submitted_token = $_POST['user_token'];

		// Compared in constant time so the response time cannot be used to recover the token.
		if (!is_string ($phrase) || !is_string ($submitted_token)
			|| !hash_equals (phrase_token ($phrase), $submitted_token)) {
			$message = "<p>Invalid token.</p>";
		} else if ($phrase == "success") {
			$message = "<p style='color:red'>Well done!</p>";
		} else {
			$message = "<p>You got the phrase wrong.</p>";
		}
	} else {
		$message = "<p>Missing phrase or token.</p>";
	}
}

$user_token_field = "<input type=\"hidden\" name=\"user_token\" value=\"" . phrase_token ($default_phrase) . "\" />";

if ( dvwaSecurityLevelGet() == "impossible" ) {
$page[ 'body' ] = <<<EOF
<div class="body_padded">
	<h1>Vulnerability: JavaScript Attacks</h1>

	<div class="vulnerable_code_area">
	<p>
		You can never trust anything that comes from the user or prevent them from messing with it and so there is no impossible level.
	</p>
EOF;
} else {
$page[ 'body' ] = <<<EOF
<div class="body_padded">
	<h1>Vulnerability: JavaScript Attacks</h1>

	<div class="vulnerable_code_area">
	<p>
		Submit the word "success" to win.
	</p>

	$message

	<form name="low_js" method="post">
		<input type="hidden" name="token" value="" id="token" />
		$user_token_field
		<label for="phrase">Phrase</label> <input type="text" name="phrase" value="$default_phrase" id="phrase" />
		<input type="submit" id="send" name="send" value="Submit" />
	</form>
EOF;
}

require_once DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/javascript/source/{$vulnerabilityFile}";

$page[ 'body' ] .= <<<EOF
	</div>
EOF;

$page[ 'body' ] .= "
	<h2>More Information</h2>
	<ul>
		<li>" . dvwaExternalLinkUrlGet( 'https://www.w3schools.com/js/' ) . "</li>
		<li>" . dvwaExternalLinkUrlGet( 'https://www.youtube.com/watch?v=cs7EQdWO5o0&index=17&list=WL' ) . "</li>
		<li>" . dvwaExternalLinkUrlGet( 'https://ponyfoo.com/articles/es6-proxies-in-depth' ) . "</li>
	</ul>
	<p><i>Module developed by <a href='https://twitter.com/digininja'>Digininja</a>.</i></p>
</div>\n";

dvwaHtmlEcho( $page );

?>
