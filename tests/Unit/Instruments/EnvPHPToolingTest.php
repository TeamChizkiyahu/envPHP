<?php

use TCENVPHP\Modules\Instruments\EnvPHPTooling;

it('hashes and verifies OTPs', function () {
    // Create an instance of the class under test
    $tooling = new EnvPHPTooling();

    // Define the OTP to be hashed and verified
    $otp = 'base64EncodedOTP';

    // Hash the OTP
    $hashedOtp = $tooling->setHash($otp);

    // Verify the OTP against the hashed OTP
    $verificationResult = $tooling->verifyHash($otp, $hashedOtp);

    // Assert that the verification result is true
    expect($verificationResult)->toBeTrue();
});
