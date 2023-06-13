<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Conjoins;

use InvalidArgumentException;


/**
 * Interface ScramblerInterface
 *
 * This interface defines a contract for classes that scramble data using the XOR operation.
 *
 * @package TCENVPHP\Modules\Conjoins
 */
interface ScramblerInterface
{
    /**
     * Scramble the given data using the XOR operation.
     *
     * @param string $data The data to scramble.
     * @param string $otp The one-time pad to use for the XOR operation.
     * @return string The scrambled data.
     * @throws InvalidArgumentException if the data or the one-time pad are empty.
     */
    public function xor_scramble($data, $otp);
}


/**
 * Class Scrambler
 *
 * This class provides a method for scrambling data using the XOR operation.
 *
 * @package TCENVPHP\Modules\Conjoins
 */
class Scrambler implements ScramblerInterface
{
    public function xor_scramble($data, $otp)
    {
        // $otp must be decoded prior to use of xor_scramble
        $data = base64_decode($data);

        if (empty($data) || empty($otp)) {
            throw new InvalidArgumentException('Data and OTP must not be empty.');
        }

        $dataLen = strlen($data);
        $otpLen = strlen($otp);
        $scrambled = '';

        for ($i = 0; $i < $dataLen; $i++) {
            $scrambled .= chr(ord($data[$i]) ^ ord($otp[$i % $otpLen]));
        }

        $scrambled = base64_encode($scrambled);
        return $scrambled;
    }
}
