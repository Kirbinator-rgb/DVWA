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

$message = "";
// Check what was sent in to see if it was what was expected.
//
// The token that decides this is now issued by the server and held in the session. What was
// here before recomputed a fixed function of the phrase -- md5(str_rot13(...)), a reversed
// string, a doubled SHA-256 -- and compared it to what the caller sent. Every one of those is
// derivable from data the client already has, using an algorithm the page itself ships to the
// browser, so the "token" proved only that the sender could read the source. A value the client
// can compute is not evidence about the client, no matter how it is hashed. The submitted
// `token` field is left alone so the level's own script still demonstrates the point; the
// server simply no longer treats it as authority.
if ($_SERVER['REQUEST_METHOD'] == "POST") {
	if (array_key_exists ("phrase", $_POST) && array_key_exists ("user_token", $_POST)) {

		$phrase = $_POST['phrase'];
		$submitted_token = $_POST['user_token'];
		$session_token = array_key_exists ("session_token", $_SESSION) ? $_SESSION['session_token'] : "";

		// Compared in constant time so the response time cannot be used to recover the token.
		if (!is_string ($submitted_token) || $session_token === "" || !hash_equals ($session_token, $submitted_token)) {
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

// Issued after the check above, so each token is accepted once and a captured one cannot be
// replayed.
generateSessionToken();
$user_token_field = tokenField();

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
		<label for="phrase">Phrase</label> <input type="text" name="phrase" value="ChangeMe" id="phrase" />
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
