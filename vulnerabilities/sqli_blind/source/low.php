<?php

// This level now carries impossible.php's control verbatim, including the anti-CSRF check that
// the previous version here deliberately dropped. Dropping it was the only thing that separated
// the two files, and it was the wrong call: checkToken() does redirect rather than return, but
// index.php now renders tokenField() at this level too, so a caller that loads the form gets a
// token and reaches the handler exactly as it does at the impossible level.
//
// The control itself is unchanged: the identifier must be numeric, it is cast to an integer, and
// it is bound as a parameter, so a blind injection has neither a string to break out of nor a
// place to graft a condition onto. The 404 on a missing row is kept, since that response is the
// only signal this endpoint gives and it must not vary with anything but existence.


if( isset( $_GET[ 'Submit' ] ) ) {
	// Check Anti-CSRF token
	checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
	$exists = false;

	// Get input
	$id = $_GET[ 'id' ];

	// Was a number entered?
	if(is_numeric( $id )) {
		$id = intval ($id);
		switch ($_DVWA['SQLI_DB']) {
			case MYSQL:
				// Check the database
				$data = $db->prepare( 'SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;' );
				$data->bindParam( ':id', $id, PDO::PARAM_INT );
				$data->execute();

				$exists = $data->rowCount();
				break;
			case SQLITE:
				global $sqlite_db_connection;

				$stmt = $sqlite_db_connection->prepare('SELECT COUNT(first_name) AS numrows FROM users WHERE user_id = :id LIMIT 1;' );
				$stmt->bindValue(':id',$id,SQLITE3_INTEGER);
				$result = $stmt->execute();
				$result->finalize();
				if ($result !== false) {
					// There is no way to get the number of rows returned
					// This checks the number of columns (not rows) just
					// as a precaution, but it won't stop someone dumping
					// multiple rows and viewing them one at a time.

					$num_columns = $result->numColumns();
					if ($num_columns == 1) {
						$row = $result->fetchArray();

						$numrows = $row[ 'numrows' ];
						$exists = ($numrows == 1);
					}
				}
				break;
		}

	}

	// Get results
	if ($exists) {
		// Feedback for end user
		$html .= '<pre>User ID exists in the database.</pre>';
	} else {
		// User wasn't found, so the page wasn't!
		header( $_SERVER[ 'SERVER_PROTOCOL' ] . ' 404 Not Found' );

		// Feedback for end user
		$html .= '<pre>User ID is MISSING from the database.</pre>';
	}
}

// Generate Anti-CSRF token
generateSessionToken();

?>
