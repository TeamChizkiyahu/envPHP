<?php

use TCENVPHP\Auth\Rsa;
use TCENVPHP\Modules\Constants\Core\Consts;
use TCENVPHP\Modules\Conjoins\Scrambler;


it('returns a string when provided valid input to encrypt data', function () {
    $data = 'testData';
    $rsa_config = array(
        "digest_alg" => "sha512",
        "private_key_bits" => Consts::getKey4096(),
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    );

    // Create the private and public key
    $res = openssl_pkey_new($rsa_config);

    // Extract the public key
    openssl_pkey_export($res, $privateKey);
    $publicKeyDetails = openssl_pkey_get_details($res);
    $publicKey = $publicKeyDetails['key'];

    $otp = base64_encode(random_bytes(32));

    $scrambler = Mockery::mock(Scrambler::class);
    $scrambler->shouldReceive('xor_scramble')
        ->andReturnUsing(function ($data, $otp) {
            return $data ^ $otp;
        });

    $rsa = new Rsa($scrambler);

    $encryptedData = $rsa->rsa_encrypt_data($data, $publicKey, $otp);

    expect($encryptedData)->toBeString();
});


it('throws exception for invalid OTP', function () {
    $data = 'testData';
    $config = array(
        "digest_alg" => "sha512",
        "private_key_bits" => Consts::getKey4096(),
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    );

    // Create the private and public key
    $res = openssl_pkey_new($config);

    // Extract the public key
    openssl_pkey_export($res, $privateKey);
    $publicKeyDetails = openssl_pkey_get_details($res);
    $publicKey = $publicKeyDetails['key'];

    $otp = 'invalid OTP';  // Invalid OTP

    $scrambler = Mockery::mock(Scrambler::class);
    $rsa = new Rsa($scrambler);

    expect(function () use ($rsa, $data, $publicKey, $otp) {
        $rsa->rsa_encrypt_data($data, $publicKey, $otp);
    })->toThrow(RuntimeException::class, 'Invalid OTP provided.');
});


it('throws exception for invalid key', function () {
    $data = 'testData';
    $key = 'invalid key';  // Invalid key
    $otp = base64_encode(random_bytes(32));

    $scrambler = Mockery::mock(Scrambler::class);
    $rsa = new Rsa($scrambler);

    expect(function () use ($rsa, $data, $key, $otp) {
        $rsa->rsa_encrypt_data($data, $key, $otp);
    })->toThrow(RuntimeException::class, 'Invalid key provided.');
});
