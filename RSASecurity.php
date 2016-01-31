<?php
ini_set('max_execution_time', 300); //300 seconds = 5 minutes
include('Crypt/RSA.php');

class RSASecurity {
	// Variable RSA
	private static $rsa;

	// Set intance of rsa
	public static function setInstance() {
		if(self::$rsa == null)
			self::$rsa = new Crypt_RSA();
	}

	// Encrypt rsa
	public static function encrypt($text) {
		// Checking instance
		self::setInstance();

        self::$rsa->setHash('sha1');
        self::$rsa->setMGFHash('sha1');
        self::$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
        self::$rsa->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
        self::$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);

        // Create key
		$keys = self::$rsa->createKey(1024); 
		// Load key public
		self::$rsa->loadKey($keys['publickey']);
		// Encrypt
	    $cipherText = self::$rsa->encrypt($text);

	    $data = array();
	    // Encrypt using base64
	    $data['key'] = base64_encode($keys['privatekey']);
	    $data['chipertext'] = base64_encode($cipherText);
	    return $data;		
	}

	// Decrypt rsa
	public static function decrypt($chipertext, $publickey) {
		// Checking instance
		self::setInstance();
        self::$rsa->setHash('sha1');
        self::$rsa->setMGFHash('sha1');
        self::$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
        self::$rsa->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
        self::$rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);

		// Decrypt base64
	    self::$rsa->loadKey(base64_decode($publickey));  
	    $plainText = self::$rsa->decrypt(base64_decode($chipertext));
	    return $plainText;
	}
}


// How to use ?
// Arg 1 is your text message
// Resulting 2 arrays

// echo print_r(RSASecurity::encrypt("HELLO WORLD"));


// How to use ?
// Arg 1 is your plain text
// Arg 2 is your private key after encode to base64

// Example to decrypting
echo RSASecurity::decrypt('M7B/nZFLhoJykGmjocDqqial75LiNH6WoFU2pD/th5s3YjcPW2trDOBxwbpmsxap2vcgwET5i+Zu
y9lk0ElL5X5Pa2Bb6dd/ANwLi7o7u2GjpU6QXDTXO46VpnGRWA05hLjY5KqNf2LsDAa5y6FVb4/h
JJskpEu9R8kp05AuDIM','LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDZVFJQkFEQU5CZ2txaGtpRzl3MEJB
UUVGQUFTQ0FtTXdnZ0pmQWdFQUFvR0JBT1piVDNiVHFOeVcvLzNUd2xzaVNQSVVrZjhoCjB3MDZn
eU5OTnZ3eWlvMjMzNFVjOHlhY0VyZStxMGUxUWVLdnlPSmxxL2NXNFhlbjh3Si9zYzhDRTN0eCtQ
MndOMUVWdGQ5a3pwNlgKaERNeUZTSnpoRmRXT3gwR2czNXhhYjE0c0dxOGxlVllaOXE4N21qdTl5
ay9kb1loSGoxbWdiQ2xaWnAvZ0VmdUVSMWJBZ01CQUFFQwpnWUVBcGcwb1NSWG1ZYTBQdDE5UWVQ
Vkw5QVZVQUwvWExYQUNYQTRyRnIwd0YxeDJhYlFtcXF4UzZkVXVEckRnWDVJcmt0ZUxrTUFUCm8z
ZVR1emRsYXoycDRESjZXNnpqcUpLSGRTeGhFdlBybjdsR2t5aGF3SDhwcHZZQXl6Zzg1RW1TQU4y
ZDY2dUFQNFltSFlTOVJHZ08KY0dhL0l0aVZoeVJuZ3ZJNjc0eFVQOUVDUVFEejZ4RTNsUkIxR1Vr
alp5S2JzK2toRUhBT0dKaERkMWNqR0owZGZpR0o5Zm14RkVRZgpDaW9Bd1VMYnI2eTBodVYyaGVk
MnNEV2JhUitMTnA3cmFLTkhBa0VBOGNSSHFpZkcrTTlFSTJTYTVnYklwYk5nM24yWGRpaFRXR204
ClQ2T0k2Ti9SbjIxcnpzRTlzSVJPNkZYbnlWdDJIRmNtQUs0TnBIbktaWlk5eTc1M1RRSkJBTDRU
L2V2Qmh2eXB3cndMQUFZMEVrVkkKNlBtakl1ellVQmd5Y3lWcmlEbFpiTVlZMCtrWVk1a0pBYy91
dTNoRzh3UUUzMVkzaE43aDhjbnJ1N1laYWJzQ1FRRHVWZ0FNRjBDSQpnZE43VEsrRE9vYk5DMFBn
c2xFQk00bk9iQll2TUZsRXNYaTJRU2w1WG5rUkxhMllUeSs4Q2dVcXRTTUtvb3RpYklvQmtaWUQ2
QlUxCkFrRUE0dGVlanY2bGtZbG52TUdlR0Z4cXk4RGNBZlJRK3phcmhLdXd3ZWIzTXBScnhjY0kw
K3lCSHBZdWFBQytVMXFhbkZjcTcyYk0KM2RLZTZNTlo5QitsRHcKCi0tLS0tRU5EIFJTQSBQUklW
QVRFIEtFWS0tLS0t');

// Show "HELLO WORLD AJA"