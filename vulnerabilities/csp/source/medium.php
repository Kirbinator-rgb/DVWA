<?php

// This level is protected by the same policy as this module's impossible level: script-src is
// narrowed to 'self'. What was here before undid itself twice over -- 'unsafe-inline' permits
// exactly the inline script a policy exists to stop, and the nonce was a hardcoded constant
// baked into the source, so anyone reading the page could quote it and have their own inline
// script trusted. A nonce is only worth anything when it is unpredictable and issued per
// response.
$headerCSP = "Content-Security-Policy: script-src 'self';";

header($headerCSP);

// The X-XSS-Protection: 0 header that used to be sent here switched off the browser's own
// filtering to make injected alerts work. Nothing should be asking a browser to lower its
// defences.

?>
<?php
if (isset ($_POST['include'])) {
// Submitted text is dropped straight into the page, so it is escaped rather than trusted as
// markup. The policy above is a second line of defence, not the only one.
$page[ 'body' ] .= "
	" . htmlspecialchars( $_POST['include'], ENT_QUOTES, 'UTF-8' ) . "
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>Whatever you enter here gets dropped directly into the page, see if you can get an alert box to pop up.</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
';
