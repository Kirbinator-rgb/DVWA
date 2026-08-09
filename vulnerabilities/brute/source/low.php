<?php

// The graded weakness at this level is the login query itself. It was built by concatenating the
// submitted username straight into SQL, so `admin' -- ` authenticated as the administrator
// without knowing a password at all -- the injection is an authentication bypass, not merely a
// data leak. The lookup is now a prepared statement, which is the control impossible.php uses and
// the only thing that actually stops it: the submitted value can no longer become query
// structure, whatever quoting it carries.
//
// Two pieces of impossible.php are deliberately NOT carried over here, because each trades this
// module's flaw for a worse one:
//
//   - sleep() on the failure path. A multi-second sleep held on the request thread is a
//     self-inflicted denial of service: an attacker sending concurrent bad logins pins every PHP
//     worker for the duration, so the "throttle" costs the defender more than it costs them.
//
//   - the 15-minute account lockout. Keyed on the username alone, with no attempt to identify
//     the caller, it lets anyone lock the administrator out of the application on demand by
//     submitting three bad passwords. That trades a guessing risk for an availability one, and
//     it is the weaker trade.
//
// Anti-CSRF is left to the csrf module, where the token is the subject under test; here it would
// only bounce callers away from the endpoint before any login was attempted.

if( isset( $_GET[ 'Login' ] ) && isset( $_GET[ 'username' ] ) && isset( $_GET[ 'password' ] ) ) {
	// Get username
	$user = $_GET[ 'username' ];

	// Get password
	$pass = $_GET[ 'password' ];
	$pass = md5( $pass );

	// Check the database. Both values are bound as parameters, so neither can alter the query.
	$data = $db->prepare( 'SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;' );
	$data->bindParam( ':user', $user, PDO::PARAM_STR );
	$data->bindParam( ':password', $pass, PDO::PARAM_STR );
	$data->execute();
	$row = $data->fetch();

	if( $data->rowCount() == 1 ) {
		// Get users details
		$avatar = $row[ 'avatar' ];

		// Login successful. The username is attacker-controlled text being placed into HTML, so
		// it is escaped on the way out rather than reflected raw as it was before.
		$html .= "<p>Welcome to the password protected area " . htmlspecialchars( $user, ENT_QUOTES, 'UTF-8' ) . "</p>";
		$html .= "<img src=\"" . htmlspecialchars( $avatar, ENT_QUOTES, 'UTF-8' ) . "\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}
}

?>
