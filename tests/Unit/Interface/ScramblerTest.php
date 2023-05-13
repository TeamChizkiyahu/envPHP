<?php

use TCENVPHP\Modules\Interface\Scrambler;

it('scrambles data using xor and otp', function () {
    $data = base64_encode('testData'); // we must base64 encode because the method decodes it
    $otp = 'testOTP';
    $scrambler = new Scrambler();

    $scrambled = $scrambler->xor_scramble($data, $otp);

    // Verify that the scrambled data is a base64 encoded string
    expect($scrambled)->toBeString();
    expect(base64_decode($scrambled, true))->not()->toBeFalse();
});

it('throws an exception if data is empty', function () {
    $data = '';
    $otp = 'testOTP';
    $scrambler = new Scrambler();

    expect(function () use ($scrambler, $data, $otp) {
        $scrambler->xor_scramble($data, $otp);
    })->toThrow(InvalidArgumentException::class, 'Data and OTP must not be empty.');
});

it('throws an exception if otp is empty', function () {
    $data = base64_encode('testData'); // we must base64 encode because the method decodes it
    $otp = '';
    $scrambler = new Scrambler();

    expect(function () use ($scrambler, $data, $otp) {
        $scrambler->xor_scramble($data, $otp);
    })->toThrow(InvalidArgumentException::class, 'Data and OTP must not be empty.');
});

it('can unscramble the data', function () {
    $data = 'testData';
    $otp = 'testOTP';
    $scrambler = new Scrambler();

    $scrambled = $scrambler->xor_scramble(base64_encode($data), $otp);

    $unscrambled = $scrambler->xor_scramble($scrambled, $otp);

    // After scrambling and unscrambling the data, we should get the original data back
    expect(base64_decode($unscrambled))->toBe($data);
});
