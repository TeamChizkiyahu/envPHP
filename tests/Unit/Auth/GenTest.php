<?php

use TCENVPHP\Modules\Constants\Core\AnonConsts;

use TCENVPHP\Modules\Interface\Scrambler;
use TCENVPHP\Modules\Interface\VerifyPseudo;

use TCENVPHP\Auth\Gen;



it('generates RSA key pair', function () {
    $otp = base64_encode(random_bytes(32));
    $salt = base64_encode(random_bytes(32));

    $verifyPseudo = Mockery::mock(VerifyPseudo::class);
    $scrambler = Mockery::mock(Scrambler::class);
    $scrambler->shouldReceive('xor_scramble')
        ->andReturnUsing(function ($data, $otp) {
            return $data ^ $otp;
        });

    $gen = new Gen($verifyPseudo, $scrambler);

    $keyPair = $gen->generate_rsa_key_pair($otp, $salt);

    expect($keyPair)->toBeArray();
    expect($keyPair)->toHaveKey('private_key');
    expect($keyPair)->toHaveKey('public_key');
    expect($keyPair)->toHaveKey('hashes');

    expect($keyPair['private_key'])->toBeString();
    expect($keyPair['public_key'])->toBeString();
    expect($keyPair['hashes'])->toBeString();
});




it('generates random bytes for a value as a length between 90 and 150', function () {
    $verifyPseudo = Mockery::mock(VerifyPseudo::class);
    $scrambler = Mockery::mock(Scrambler::class);

    $anonConsts = new AnonConsts();
    $randomBytesLength = $anonConsts->getRand();
    $randomBytes = random_bytes($randomBytesLength);

    $verifyPseudo->shouldReceive('verifySecurePseudoRandomBytes')
        ->andReturn($randomBytes);

    $gen = new Gen($verifyPseudo, $scrambler);
    $key = $gen->generate_encryption_key();

    expect(strlen($key))->toBeGreaterThanOrEqual(90);
    expect(strlen($key))->toBeLessThanOrEqual(150);
});
