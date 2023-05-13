<?php

use TCENVPHP\Modules\Constants\Core\Consts;
use TCENVPHP\Auth\Aes;
use TCENVPHP\Modules\Interface\VerifyPseudo;


it('encrypts data and throws an exception when IV is not secure', function () {
    $data = 'testData';
    $key = base64_encode(random_bytes(32));
    $salt = base64_encode(random_bytes(32));

    $mockGenerator = Mockery::mock(VerifyPseudo::class);
    $mockGenerator->shouldReceive('verifySecurePseudoRandomBytes')
        ->andThrow(new \RuntimeException('Unable to generate a cryptographically secure random bytes.'));

    $aes = new Aes($mockGenerator);

    expect(function () use ($aes, $data, $key, $salt) {
        $aes->encrypt_data($data, $key, $salt);
    })->toThrow(new RuntimeException('Unable to generate a cryptographically secure random bytes.'));
});

it('decrypts encrypted data correctly', function () {
    $data = 'testData';
    $key = base64_encode(random_bytes(32));
    $salt = base64_encode(random_bytes(32));


    $mockGenerator = Mockery::mock(VerifyPseudo::class);
    $mockGenerator->shouldReceive('verifySecurePseudoRandomBytes')
        ->andReturn(random_bytes(Consts::getIvBinLength()));


    $aes = new Aes($mockGenerator);

    $encryptedData = $aes->encrypt_data($data, $key, $salt);
    $decryptedData = $aes->decrypt_data($encryptedData, $key, $salt);

    expect($decryptedData)->toBe($data);
});


it('throws an exception when decryption fails', function () {
    $data = 'testData';
    $key = base64_encode(random_bytes(32));
    $salt = base64_encode(random_bytes(32));


    $mockGenerator = Mockery::mock(VerifyPseudo::class);
    $mockGenerator->shouldReceive('verifySecurePseudoRandomBytes')
        ->andReturn(random_bytes(Consts::getIvBinLength()));

    $aes = new Aes($mockGenerator);

    // Alter the encrypted data to cause a decryption failure
    $encryptedData = $aes->encrypt_data($data, $key, $salt) . 'extra bytes';

    expect(function () use ($aes, $encryptedData, $key, $salt) {
        $aes->decrypt_data($encryptedData, $key, $salt);
    })->toThrow(new RuntimeException('Retrieve RSA Private Key Decryption failed.'));
});
