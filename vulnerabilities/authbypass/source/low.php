<?php
/*

Only the admin user is allowed to access this page.

This level used to carry no check at all. The module was kept out of reach by leaving its link
out of the menu for non-admin users -- see the dvwaHtmlEcho function in
dvwa/includes/dvwaPage.inc.php -- but a link that is not drawn is not a control. The URL is
still there, it is guessable, and it is listed in this application's own source. Navigation
decides what a user is *shown*; only a server-side check decides what a user may *do*, and that
check has to live on the request path rather than in the page that links to it.

The same check the medium, high and impossible levels use is applied here.

*/

if (dvwaCurrentUser() != "admin") {
	print "Unauthorised";
	http_response_code(403);
	exit;
}
?>
