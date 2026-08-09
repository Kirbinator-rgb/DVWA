<?php
define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaDatabaseConnect();

/*
Only the admin is allowed to change user details.

The check used to apply on impossible only, so at every other level any authenticated user could
rewrite any other account's details -- including the admin's -- just by POSTing to this URL. The
page that links here checks who is asking; this endpoint has to do the same, because it is
reachable on its own and nothing about being called by fetch() makes a caller trustworthy.
*/

if (dvwaCurrentUser() != "admin") {
	print json_encode (array ("result" => "fail", "error" => "Access denied"));
	http_response_code(403);
	exit;
}

if ($_SERVER['REQUEST_METHOD'] != "POST") {
	$result = array (
						"result" => "fail",
						"error" => "Only POST requests are accepted"
					);
	echo json_encode($result);
	exit;
}

try {
	$json = file_get_contents('php://input');
	$data = json_decode($json);
	if (is_null ($data)) {
		$result = array (
							"result" => "fail",
							"error" => 'Invalid format, expecting "{id: {user ID}, first_name: "{first name}", surname: "{surname}"}'

						);
		echo json_encode($result);
		exit;
	}
} catch (Exception $e) {
	$result = array (
						"result" => "fail",
						"error" => 'Invalid format, expecting \"{id: {user ID}, first_name: "{first name}", surname: "{surname}\"}'

					);
	echo json_encode($result);
	exit;
}

// Every field is required and typed before it is used, so a missing key cannot fall through as
// an empty fragment of SQL.
if (!isset ($data->first_name, $data->surname, $data->id)
	|| !is_string ($data->first_name) || !is_string ($data->surname) || !is_numeric ($data->id)) {
	print json_encode (array (
						"result" => "fail",
						"error" => 'Invalid format, expecting "{id: {user ID}, first_name: "{first name}", surname: "{surname}"}'
					));
	exit;
}

$first_name = $data->first_name;
$surname    = $data->surname;
$user_id    = intval ($data->id);

// Bound as parameters. The three values used to be concatenated into the statement, so a
// surname of  ' , first_name = 'x  rewrote the rest of the query, and the numeric id was not
// quoted at all -- so `1 OR 1=1` updated every row in the table at once. Bound values are sent
// separately from the statement and can never be read as SQL, whatever they contain.
$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "UPDATE users SET first_name = ?, last_name = ? WHERE user_id = ?");
if (!$stmt) {
	print json_encode (array ("result" => "fail", "error" => "Could not update the user"));
	exit;
}

mysqli_stmt_bind_param($stmt, "ssi", $first_name, $surname, $user_id);
$ok = mysqli_stmt_execute($stmt);
mysqli_stmt_close($stmt);

if (!$ok) {
	// The database's own error text is not returned. It used to be printed straight to the
	// caller, which hands an attacker the table and column names to aim at.
	print json_encode (array ("result" => "fail", "error" => "Could not update the user"));
	exit;
}

print json_encode (array ("result" => "ok"));
exit;
?>
