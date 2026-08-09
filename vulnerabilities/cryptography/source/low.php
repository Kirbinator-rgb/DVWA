<?php

// Messages are protected with AES-256-GCM, an authenticated cipher from the platform's own
// library, laid out as iv(12) || ciphertext || tag(16) and base64 encoded.
//
// What was here before was a hand-written XOR against a repeating ten-character key. That is not
// encryption in any useful sense. XOR with a repeating key preserves the length and the
// structure of the plaintext, and because the same key bytes recur every ten characters, the
// ciphertext can be broken by frequency analysis without ever seeing the key -- the classic
// Vigenere break, and there is no key material to guess if the attacker has a single known
// plaintext, since key = ciphertext XOR plaintext falls straight out. It also provides no
// integrity whatsoever: flipping any ciphertext bit flips exactly that plaintext bit.
//
// Rolling your own is the mistake being corrected here. The rule is to use a vetted
// authenticated construction, and GCM verifies its tag before returning any plaintext, so
// tampering is rejected instead of quietly decrypted.
function encrypt_message($cleartext, $key) {
	$iv = random_bytes(12);
	$ciphertext = openssl_encrypt($cleartext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($ciphertext === false) {
		throw new Exception ("Encryption failed");
	}
	return $iv . $ciphertext . $tag;
}

function decrypt_message($raw, $key) {
	// 12 byte IV + at least one byte of ciphertext + 16 byte tag.
	if (strlen($raw) < 29) {
		throw new Exception ("Message could not be decoded");
	}

	$iv         = substr($raw, 0, 12);
	$tag        = substr($raw, -16);
	$ciphertext = substr($raw, 12, -16);

	$cleartext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
	if ($cleartext === false) {
		throw new Exception ("Message could not be decoded");
	}
	return $cleartext;
}

// A passphrase is not a key: aes-256-gcm needs 32 bytes, so it is derived rather than used raw.
$key = hash('sha256', "wachtwoord", true);

// The login credential is stored as a bcrypt hash and compared with password_verify. It used to
// be the literal string "Olifant" sitting in this file, and the "intercepted" message published
// below was that same word under the XOR cipher -- so the password was recoverable twice over,
// by reading the source or by breaking the toy cipher. A hash cannot be run backwards, and the
// sample message below no longer carries a credential.
define ('LOGIN_PASSWORD_HASH', '$2y$12$xbYOwM4oLaQ6qeNJm9fNF.9GSnuZ7kfxatpDUfPlIjdu6hivMlZ3O');

$errors = "";
$success = "";
$messages = "";
$encoded = null;
$encode_radio_selected = " checked='checked' ";
$decode_radio_selected = " ";
$message = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (array_key_exists ('message', $_POST)) {
			$message = $_POST['message'];
			if (array_key_exists ('direction', $_POST) && $_POST['direction'] == "decode") {
				$encoded = decrypt_message (base64_decode ($message), $key);
				$encode_radio_selected = " ";
				$decode_radio_selected = " checked='checked' ";
			} else {
				$encoded = base64_encode(encrypt_message ($message, $key));
			}
		}
		if (array_key_exists ('password', $_POST)) {
			$password = $_POST['password'];
			// password_verify compares against the stored hash in constant time.
			if (password_verify ($password, LOGIN_PASSWORD_HASH)) {
				$success = "Welcome back user";
			} else {
				$errors = "Login Failed";
			}
		}
	} catch(Exception $e) {
		$errors = $e->getMessage();
	}
}

$html = "
		<p>
		This super secure system will allow you to exchange messages with your friends without anyone else being able to read them. Use the box below to encode and decode messages.
		</p>
		<form name=\"xor\" method='post' action=\"" . $_SERVER['PHP_SELF'] . "\">
			<p>
				<label for='message'>Message:</lable><br />
				<textarea style='width: 600px; height: 56px' id='message' name='message'>" . htmlentities ($message) . "</textarea>
			</p>
			<p>
				<input type='radio' value='encode' name='direction' id='direction_encode' " . $encode_radio_selected . "><label for='direction_encode'>Encode</label> or 
				<input type='radio' value='decode' name='direction' id='direction_decode' " . $decode_radio_selected . "><label for='direction_decode'>Decode</label>
			</p>
			<p>
				<input type=\"submit\" value=\"Submit\">
			</p>
		</form>
";

if (!is_null ($encoded)) {
	$html .= "
			<p>
				<label for='encoded'>Message:</lable><br />
				<textarea readonly='readonly' style='width: 600px; height: 56px' id='encoded' name='encoded'>" . htmlentities ($encoded) . "</textarea>
			</p>";
}

$html .= "
		<hr>
		<p>
		You have intercepted the following message.
		</p>
		<p>
		<textarea readonly='readonly' style='width: 600px; height: 28px' id='encoded' name='encoded'>0jzh7Py3Gq405EveRYlR2GT59V1Xcn9jDd7y7m3/Z/hmVvBYaH5+cpycS+/ndpPK/mtkBtI2jJp7xbbWraSE</textarea>
		</p>
";

if ($errors != "") {
	$html .= '<div class="warning">' . $errors . '</div>';
}

if ($messages != "") {
	$html .= '<div class="nearly">' . $messages . '</div>';
}

if ($success != "") {
	$html .= '<div class="success">' . $success . '</div>';
}

$html .= "
		<form name=\"ecb\" method='post' action=\"" . $_SERVER['PHP_SELF'] . "\">
			<p>
				<label for='password'>Password:</lable><br />
<input type='password' id='password' name='password'>
			</p>
			<p>
				<input type=\"submit\" value=\"Login\">
			</p>
		</form>
";
?>
