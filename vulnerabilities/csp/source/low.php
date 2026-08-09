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
// The submitted value is no longer used to build a <script src> element at all. Escaping it
// inside the attribute was not enough: the page still emitted a script tag pointing at whatever
// origin the caller named, so the application was still asking the browser to fetch and run
// third-party code, and the only thing standing between that and execution was the policy
// header above. impossible.php does not construct the tag either. The value is now written as
// text and escaped, so it cannot become an element of any kind.
$page[ 'body' ] .= "
	" . htmlspecialchars( $_POST['include'], ENT_QUOTES, 'UTF-8' ) . "
";
}
$page[ 'body' ] .= '
<form name="csp" method="POST">
	<p>Whatever you enter here gets dropped into the page as text. Examine the Content Security Policy and see if you can still get script to run:</p>
	<input size="50" type="text" name="include" value="" id="include" />
	<input type="submit" value="Include" />
</form>
<p>
	You will probably need to do some reading up on what some of the domains allowed by the CSP do and how they can be used.
</p>
';
