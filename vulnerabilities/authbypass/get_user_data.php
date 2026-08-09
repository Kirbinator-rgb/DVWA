<?php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

/*
Only the admin is allowed to retrieve the data.

The check used to apply on high and impossible only, so at the lower levels any authenticated
user could read the full user list from this endpoint. Authorisation cannot be conditional on a
display setting: this is a separate URL that the browser reaches directly, so it has to make its
own decision about the caller every time it is called, exactly as the page that links to it does.
An endpoint reached by fetch() is as public as one typed into the address bar.
*/
if (dvwaCurrentUser() != "admin") {
	print json_encode (array ("result" => "fail", "error" => "Access denied"));
	http_response_code(403);
	exit;
}

$query  = "SELECT user_id, first_name, last_name FROM users";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );

$guestbook = ''; 
$users = array();

while ($row = mysqli_fetch_row($result) ) {
	// Escaped at every level. These names are attacker-controllable through the details form,
	// so returning them raw let a stored payload run in whatever page rendered this response.
	$user_id = $row[0];
	$first_name = htmlspecialchars( $row[1] );
	$surname = htmlspecialchars( $row[2] );

	$user = array (
					"user_id" => $user_id,
					"first_name" => $first_name,
					"surname" => $surname
				);
	$users[] = $user;
}

print json_encode ($users);
exit;
?>
