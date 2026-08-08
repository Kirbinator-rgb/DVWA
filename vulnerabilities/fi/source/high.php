<?php

// This level is protected by the same control as this module's impossible level, which is
// DVWA's own worked answer for this vulnerability class: the page to include is chosen from a
// fixed list rather than taken from the request, so no traversal, wrapper or remote URL can
// reach include().
//
// Unlike impossible.php, a request that names no page at all is left alone rather than being
// rejected outright. index.php redirects to the default page when $file is unset, and refusing
// the bare landing request would break the module's own entry point instead of the attack.

// Only allow include.php or file{1..3}.php
$configFileNames = [
    'include.php',
    'file1.php',
    'file2.php',
    'file3.php',
];

if( isset( $_GET[ 'page' ] ) ) {
    // The page we wish to display
    $file = $_GET[ 'page' ];

    if( !in_array($file, $configFileNames) ) {
        // This isn't the page we want!
        echo "ERROR: File not found!";
        exit;
    }
}

?>
