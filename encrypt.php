<?php
    include('Crypt/RSA.php');
    set_time_limit(0);

    $rsa = new Crypt_RSA();
    $rsa->setHash('sha1');
    $rsa->setMGFHash('sha1');
    $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);

    $rsa->loadKey(file_get_contents('public.key')); // public key

    $plaintext  = 'Hello World!';
    $ciphertext = $rsa->encrypt($plaintext);
    $md5        = md5($ciphertext);
    file_put_contents('md5.txt', $md5);
    file_put_contents('encrypted.txt', base64_encode($ciphertext));

    echo base64_encode($ciphertext);

?>