<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ]   = 'Vulnerability: DOM Based Cross Site Scripting (XSS)' . $page[ 'title_separator' ].$page[ 'title' ];
$page[ 'page_id' ] = 'xss_d';
$page[ 'help_button' ]   = 'xss_d';
$page[ 'source_button' ] = 'xss_d';

dvwaDatabaseConnect();

$vulnerabilityFile = '';
switch( dvwaSecurityLevelGet() ) {
	case 'low':
		$vulnerabilityFile = 'low.php';
		break;
	case 'medium':
		$vulnerabilityFile = 'medium.php';
		break;
	case 'high':
		$vulnerabilityFile = 'high.php';
		break;
	default:
		$vulnerabilityFile = 'impossible.php';
		break;
}

require_once DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/xss_d/source/{$vulnerabilityFile}";

# The querystring is no longer written into the page as markup at any level, so whether it is
# decoded first no longer decides whether it can be executed -- see the script below.

$page[ 'body' ] = <<<EOF
<div class="body_padded">
	<h1>Vulnerability: DOM Based Cross Site Scripting (XSS)</h1>

	<div class="vulnerable_code_area">
 
 		<p>Please choose a language:</p>

		<form name="XSS" method="GET">
			<select name="default">
				<script>
					// The language from the URL is put into the page as *data*, never as markup.
					// This used to be built by pasting the raw querystring into a document.write
					// string, so a value carrying its own quote closed the value= attribute and
					// anything after it was parsed as HTML -- the page wrote the attacker's
					// markup into its own DOM. createElement with .textContent and .value cannot
					// do that: whatever the string contains, it stays a string, so there is
					// nothing to escape and nothing to blocklist.
					(function () {
						var select = document.currentScript.parentNode;

						function addOption(value, label, disabled) {
							var option = document.createElement("option");
							option.value = value;
							option.textContent = label;
							if (disabled) {
								option.disabled = true;
							}
							select.appendChild(option);
						}

						var marker = document.location.href.indexOf("default=");
						if (marker >= 0) {
							var lang = document.location.href.substring(marker + 8);
							var next = lang.indexOf("&");
							if (next >= 0) {
								lang = lang.substring(0, next);
							}
							// Decoding is only for what the user reads. It is safe here because
							// the result is assigned as text; decodeURI throws on a malformed
							// sequence, so the raw value is shown if it cannot be decoded.
							var label = lang;
							try {
								label = decodeURI(lang);
							} catch (e) {
								label = lang;
							}
							addOption(lang, label, false);
							addOption("", "----", true);
						}

						addOption("English", "English", false);
						addOption("French", "French", false);
						addOption("Spanish", "Spanish", false);
						addOption("German", "German", false);
					})();
				</script>
			</select>
			<input type="submit" value="Select" />
		</form>
	</div>
EOF;

$page[ 'body' ] .= "
	<h2>More Information</h2>
	<ul>
		<li>" . dvwaExternalLinkUrlGet( 'https://owasp.org/www-community/attacks/xss/' ) . "</li>
		<li>" . dvwaExternalLinkUrlGet( 'https://owasp.org/www-community/attacks/DOM_Based_XSS' ) . "</li>
		<li>" . dvwaExternalLinkUrlGet( 'https://www.acunetix.com/blog/articles/dom-xss-explained/' ) . "</li>
	</ul>
</div>\n";

dvwaHtmlEcho( $page );

?>
