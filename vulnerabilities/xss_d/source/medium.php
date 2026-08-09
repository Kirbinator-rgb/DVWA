<?php

// This level now carries the same server-side control as this module's high level: the language
// is chosen from a fixed list rather than taken from the request.
//
// What was here before blocked the single string "<script". That is a blocklist, and it only
// ever removes the example everyone already knows: "</select><img src=x onerror=alert(1)>"
// contains no script tag and passed straight through. Deciding what is allowed is the only
// version of this check that does not need updating every time someone finds another element
// that runs script.
//
// The whitelist cannot be the whole answer on its own: the sink in index.php reads
// document.location.href, and anything after a '#' never reaches the server, so this check does
// not see it. It is paired with the impossible level's client-side control -- the querystring is
// no longer passed through decodeURI before being written -- which is what covers the fragment.

// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {

	# White list the allowable languages
	switch ($_GET['default']) {
		case "French":
		case "English":
		case "German":
		case "Spanish":
			# ok
			break;
		default:
			header ("location: ?default=English");
			exit;
	}
}

?>
