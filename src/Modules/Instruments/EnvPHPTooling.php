<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Instruments;


/**
 * Class EnvPHPTooling
 *
 * This class provides methods for hashing and verifying hashes of one-time-passwords (OTPs).
 * 
 * This namespace is used to define classes that provide utility methods for the TCENVPHP application.
 *
 * @package TCENVPHP\Modules\Instruments
 */
final class EnvPHPTooling
{

    /**
     * Hash the given OTP.
     *
     * @param string $otp The OTP to hash, is needed as a base64_encode.
     * @return string The hashed OTP.
     */
    public function setHash($otp)
    {
        $votp = base64_decode($otp);
        $hashed_id = password_hash($votp, PASSWORD_DEFAULT);
        $hashed_id = base64_encode($hashed_id);
        return $hashed_id;
    }

    /**
     * Verify a given OTP against a hashed OTP.
     *
     * @param string $otp The OTP to verify, is needed as a base64_encode.
     * @param string $hashed_id The hashed OTP to compare against.
     * @return bool True if the OTP matches the hashed OTP, false otherwise.
     */
    public function verifyHash($otp, $hashed_id)
    {
        $otp = base64_decode($otp);
        $hashed_id = base64_decode($hashed_id);
        $verify = password_verify($otp, $hashed_id);
        return $verify;
    }
}
