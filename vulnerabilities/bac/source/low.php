<?php
if (!defined('DVWA_WEB_PAGE_TO_ROOT')) {
    define('DVWA_WEB_PAGE_TO_ROOT', '../../../');
}

// Who is asking is decided from the authenticated session, never from anything the caller
// sends. This is the same control the impossible level uses; what was here before compared the
// requested profile against a `user_id` **cookie**, and a cookie is just a request header the
// user can edit, so "you can only view your own profile" was enforced against a value the
// attacker chose. Identity has to come from the server side of the session.
$current_user = dvwaCurrentUser();
$current_user_id = 0;
$role = '';

$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT user_id, role FROM users WHERE user = ? LIMIT 1");
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $current_user);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    if ($result && $row = mysqli_fetch_assoc($result)) {
        $current_user_id = intval($row['user_id']);
        $role = $row['role'];
    }
    mysqli_stmt_close($stmt);
}

$html = "";
if (isset($_GET['action']) && isset($_GET['user_id'])) {
    if (!preg_match('/^\d+$/', $_GET['user_id'])) {
        $html .= "<p>Invalid user ID format. Please enter a number.</p>";
    } else {
        $id = intval($_GET['user_id']);

        // The authorisation decision comes first. Confirming the record exists before checking
        // whether the caller may see it turns the "no user found" message into an oracle for
        // enumerating which accounts exist.
        if ($id !== $current_user_id) {
            $html .= "<p>Access denied. You can only view your own profile.</p>";
        } else {
            $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = ? LIMIT 1");
            if ($stmt) {
                mysqli_stmt_bind_param($stmt, "i", $id);
                mysqli_stmt_execute($stmt);
                $result = mysqli_stmt_get_result($stmt);

                if ($result && $row = mysqli_fetch_assoc($result)) {
                    // Values out of the database are escaped on the way into the page; a stored
                    // value is not automatically a safe one.
                    $html .= "
                        <div class=\"profile-info\">
                            <h3>User Profile</h3>
                            <p>User ID: " . htmlspecialchars($row['user_id'], ENT_QUOTES, 'UTF-8') . "</p>
                            <p>Name: " . htmlspecialchars($row['first_name'], ENT_QUOTES, 'UTF-8') . " " . htmlspecialchars($row['last_name'], ENT_QUOTES, 'UTF-8') . "</p>
                            <p>Avatar: " . htmlspecialchars($row['avatar'], ENT_QUOTES, 'UTF-8') . "</p>
                        </div>";
                } else {
                    $html .= "<p>No user found with ID: " . htmlspecialchars($id, ENT_QUOTES, 'UTF-8') . "</p>";
                }
                mysqli_stmt_close($stmt);
            }
        }

        // Log access attempts
        try {
            $check_table = "SHOW TABLES LIKE 'bac_log'";
            $table_exists = mysqli_query($GLOBALS["___mysqli_ston"], $check_table);

            if ($table_exists && mysqli_num_rows($table_exists) == 0) {
                $create_table = "CREATE TABLE IF NOT EXISTS bac_log (
                   id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    user_id INT(6) NULL,
                    target_id INT(6) NULL,
                    ip_address VARCHAR(50) NULL,
                    action VARCHAR(50) NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )";
                mysqli_query($GLOBALS["___mysqli_ston"], $create_table);
            }

            // The client-supplied X-Forwarded-For header was concatenated into this INSERT, so
            // the audit log -- the one record meant to survive an attack -- was itself an
            // injection point, writable by anyone who could set a request header. Bound as a
            // parameter, its contents can no longer be read as SQL.
            $ip = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
            $log_stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "INSERT INTO bac_log (user_id, target_id, ip_address) VALUES (?, ?, ?)");
            if ($log_stmt) {
                mysqli_stmt_bind_param($log_stmt, "iis", $current_user_id, $id, $ip);
                mysqli_stmt_execute($log_stmt);
                mysqli_stmt_close($log_stmt);
            }
        } catch (Exception $e) {
            // Silently fail if logging doesn't work
        }
    }
}

// The role shown is the one the database holds for this account. It used to be read from a
// `user_role` cookie and written into the page unescaped, which let the visitor both name their
// own role and inject markup through it.
$html .= "<div class='info-banner'>Current Role: " . htmlspecialchars($role === '' ? 'regular_user' : $role, ENT_QUOTES, 'UTF-8') . "</div>";
?>
