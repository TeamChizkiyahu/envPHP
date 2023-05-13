<?php

declare(strict_types=1);

namespace TCENVPHP\Auth;

use TCENVPHP\Modules\Constants\Core\Consts;
use TCENVPHP\Modules\Interface\Scrambler;

use RuntimeException;



/**
 * Class Rsa
 *
 * This class provides methods for RSA encryption and decryption of data using a public-private key pair.
 * 
 * This namespace is used to define classes related to authentication and encryption operations for the TCENVPHP application.
 *
 * @package TCENVPHP\Auth
 */
final class Rsa
{
    /**
     * The instance of the Scrambler class used for data scrambling operations.
     *
     * @var Scrambler
     */
    private Scrambler $scrambler;

    public function __construct()
    {
        $this->scrambler = new Scrambler(); //assuming Scrambler doesn't have any dependencies
    }

    /**
     * Encrypts data with AES-256-GCM and then encrypts the AES key and initialization vector with RSA encryption.
     *
     * @param string $data The data to encrypt.
     * @param string $key The RSA public key for encrypting the AES key and initialization vector.
     * @param string $otp One-time password, base64 encoded.
     * @return string The encrypted data, scrambled with OTP.
     *
     * @throws RuntimeException If invalid key or OTP is provided.
     */
    public function rsa_encrypt_data($data, $key, $otp)
    {
        if (!openssl_pkey_get_public($key)) {
            throw new RuntimeException('Invalid key provided.');
        }

        $otp = base64_decode($otp);
        if (!$otp) {
            throw new RuntimeException('Invalid OTP provided.');
        }

        // generate random bytes for encryption
        $iv = random_bytes(Consts::getIvBinGcmLength());
        $random_hex = random_bytes(Consts::getRandHexLength());
        $tag = random_bytes(Consts::getTagLength());

        // encrypt data
        $encrypted = openssl_encrypt($data, 'aes-256-gcm', $random_hex, OPENSSL_RAW_DATA, $iv, $tag);

        //
        openssl_public_encrypt($iv, $encrypted_iv, $key, OPENSSL_PKCS1_OAEP_PADDING);
        openssl_public_encrypt($tag, $encrypted_tag, $key, OPENSSL_PKCS1_OAEP_PADDING);
        openssl_public_encrypt($random_hex, $encrypted_random_hex, $key, OPENSSL_PKCS1_OAEP_PADDING);

        $encrypted_data = base64_encode($encrypted_iv . $encrypted_tag . $encrypted_random_hex . $encrypted);
        $encrypted_scrambled_data = $this->scrambler->xor_scramble($encrypted_data, $otp);

        return $encrypted_scrambled_data;
    }

    /**
     * Decrypts data that was encrypted with the rsa_encrypt_data method.
     *
     * @param string $encrypted_data The encrypted data, scrambled with OTP.
     * @param string $private_key The RSA private key for decrypting the AES key and initialization vector.
     * @param string $otp One-time password, base64 encoded.
     * @return string The decrypted data.
     */
    public function rsa_decrypt_data($encrypted_data, $private_key, $otp)
    {

        $otp = base64_decode($otp);

        $descrambled_encoded_binary_data = $this->scrambler->xor_scramble($encrypted_data, $otp);

        $decoded_binary_data = base64_decode($descrambled_encoded_binary_data);

        $encrypted_iv_length = 512; // 4096 bits / 8
        $encrypted_tag_length = 512;
        $encrypted_hex_length = 512;

        $encrypted_iv = substr($decoded_binary_data, 0, $encrypted_iv_length);
        $encrypted_tag = substr($decoded_binary_data, $encrypted_iv_length, $encrypted_tag_length);
        $encrypted_random_hex = substr($decoded_binary_data, $encrypted_iv_length + $encrypted_tag_length, $encrypted_hex_length);
        $encrypted_data = substr($decoded_binary_data, $encrypted_iv_length + $encrypted_tag_length + $encrypted_hex_length);

        openssl_private_decrypt($encrypted_iv, $decrypted_iv, $private_key, OPENSSL_PKCS1_OAEP_PADDING);
        openssl_private_decrypt($encrypted_tag, $decrypted_tag, $private_key, OPENSSL_PKCS1_OAEP_PADDING);
        openssl_private_decrypt($encrypted_random_hex, $rand_pass, $private_key, OPENSSL_PKCS1_OAEP_PADDING);

        $decrypted_value = openssl_decrypt($encrypted_data, 'AES-256-GCM', $rand_pass, OPENSSL_RAW_DATA, $decrypted_iv, $decrypted_tag);

        return $decrypted_value;
    }
}
