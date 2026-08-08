<?php

// This level is protected by the same control as this module's impossible level, which is
// DVWA's own worked answer for this vulnerability class. Only the anti-CSRF gate that
// impossible.php also carries is left out: checkToken() redirects rather than returning, so
// requiring a token here would bounce every caller away from the endpoint instead of showing
// the input handled safely. Anti-CSRF is the csrf module's subject, not this one's.

// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {

	// Get input
	$name = htmlspecialchars( $_GET[ 'name' ] );

	// Feedback for end user
	$html .= "<pre>Hello {$name}</pre>";
}

// Generate Anti-CSRF token
generateSessionToken();

?>
