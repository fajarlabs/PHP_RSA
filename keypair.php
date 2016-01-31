<?php

set_time_limit(0);
if( file_exists('private.key') )
{
    echo base64_encode(file_get_contents('private.key'));
}
else
{
    include('Crypt/RSA.php');

    $rsa = new Crypt_RSA();
    $rsa->setHash('sha1');
    $rsa->setMGFHash('sha1');
    $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
    $rsa->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
    $rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS1);

    $res = $rsa->createKey(1024);

    $privateKey = $res['privatekey'];
    $publicKey  = $res['publickey'];

    file_put_contents('public.key', $publicKey);
    file_put_contents('private.key', $privateKey);

    echo base64_encode($privateKey);
}

?>