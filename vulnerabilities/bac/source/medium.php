<?php
if (!defined('DVWA_WEB_PAGE_TO_ROOT')) {
    define('DVWA_WEB_PAGE_TO_ROOT', '../../../');
}

// Who is asking is decided from the authenticated session. What was here before gated access on
// `token == 'user_token'` -- a fixed string, identical for everyone, printed in the page's own
// HTML comment. A shared constant is not authorisation: it proves nothing about who is asking
// and cannot distinguish one user from another, so every profile was readable by anyone who
// sent it. This is the same control the impossible level uses.
$current_user = dvwaCurrentUser();
$current_user_id = 0;

$stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT user_id FROM users WHERE user = ? LIMIT 1");
if ($stmt) {
    mysqli_stmt_bind_param($stmt, "s", $current_user);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    if ($result && $row = mysqli_fetch_assoc($result)) {
        $current_user_id = intval($row['user_id']);
    }
    mysqli_stmt_close($stmt);
}

$html = "";
if (isset($_GET['action']) && isset($_GET['user_id'])) {
    if (!preg_match('/^\d+$/', $_GET['user_id'])) {
        $html .= "<p>Invalid user ID format. Please enter a number.</p>";
    } else {
        $id = intval($_GET['user_id']);

        // Authorise before looking anything up, so the "no user found" reply cannot be used to
        // enumerate which accounts exist.
        if ($id !== $current_user_id) {
            $html .= "<p>Access denied. You can only view your own profile.</p>";
        } else {
            $stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], "SELECT first_name, last_name, user_id, avatar FROM users WHERE user_id = ? LIMIT 1");
            if ($stmt) {
                mysqli_stmt_bind_param($stmt, "i", $id);
                mysqli_stmt_execute($stmt);
                $result = mysqli_stmt_get_result($stmt);

                if ($result && $row = mysqli_fetch_assoc($result)) {
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

            // The client-supplied X-Forwarded-For header was concatenated into this INSERT,
            // making the audit log itself injectable by anyone who could set a request header.
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
?>
