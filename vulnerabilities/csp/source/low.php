<?php

// This level is protected by the same policy as this module's impossible level: script-src is
// narrowed to 'self'. The previous list allowed script from a dozen third-party hosts --
// pastebin, hastebin, unpkg, jsDelivr and friends -- any one of which will serve attacker
// authored JavaScript on request, so the policy named trusted origins that are not trustworthy
// and permitted exactly the injection it was meant to prevent.
$headerCSP = "Content-Security-Policy: script-src 'self';";

header($headerCSP);

?>
<?php
if (isset ($_POST['include'])) {
// The submitted value is placed in a quoted attribute, so it is escaped on the way out. Without
// this a value containing a quote closes src= early and appends attributes or a second tag,
// which is an injection the policy above should not have to be the only thing catching.
$page[ 'body' ] .= "
	<script src='" . htmlspecialchars( $_POST['include'], ENT_QUOTES, 'UTF-8' ) . "'></script>
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>You can include scripts from external sources, examine the Content Security Policy and enter a URL to include here:</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
<p>
	You will probably need to do some reading up on what some of the domains allowed by the CSP do and how they can be used.
</p>
';
