<?php

// This level now carries the same server-side control as this module's high level: the language
// is chosen from a fixed list rather than taken from the request. There was previously no check
// here at all.
//
// A whitelist is the whole of the server's contribution and it cannot be the whole answer: the
// sink in index.php reads document.location.href, and anything after a '#' never reaches the
// server, so this check does not see it. It is paired with the impossible level's client-side
// control -- the querystring is no longer passed through decodeURI before being written -- which
// is what covers the fragment.

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
