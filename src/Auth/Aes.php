<?php

declare(strict_types=1);

namespace TCENVPHP\Auth;

use TCENVPHP\Modules\Constants\Core\Consts;
use TCENVPHP\Modules\Interface\VerifyPseudo;

use RuntimeException;


/**
 * Class Aes
 *
 * This class provides methods for encrypting and decrypting data using the AES-256-GCM cipher.
 * 
 * This namespace is used to define classes related to authentication and encryption operations for the TCENVPHP application.
 *
 * @package TCENVPHP\Auth
 */
final class Aes
{
    /**
     * The instance of the VerifyPseudo class used to generate secure random bytes.
     *
     * @var VerifyPseudo
     */
    private VerifyPseudo $verifyPseudo;

    public function __construct()
    {
        $this->verifyPseudo = new VerifyPseudo(); //assuming VerifyPseudo doesn't have any dependencies
    }

    /**
     * Encrypt the given data using the AES-256-GCM cipher.
     *
     * @param string $data The data to encrypt.
     * @param string $key The encryption key.
     * @param string $salt The salt used in the key derivation function.
     * @return string The encrypted data, base64 encoded.
     * @throws RuntimeException If the encryption operation fails.
     */
    public function encrypt_data($data, $key, $salt)
    {
        $key = base64_decode($key);
        $salt = base64_decode($salt);

        // Derive the key using a Key Derivation Function
        $dervied_key = hash_pbkdf2('sha256', $key, $salt, Consts::getPbkdf2Iterations(), 0, true);

        $iv_length = Consts::getIvBinLength();
        $iv = $this->verifyPseudo->verifySecurePseudoRandomBytes($iv_length);

        $tag = random_bytes(Consts::getTagLength());
        $encrypted = openssl_encrypt($data, 'aes-256-GCM', $dervied_key, OPENSSL_RAW_DATA, $iv, $tag);
        return base64_encode($iv . $tag . $encrypted);
    }

    /**
     * Decrypt the given data using the AES-256-GCM cipher.
     *
     * @param string $data The data to decrypt.
     * @param string $key The decryption key.
     * @param string $salt The salt used in the key derivation function.
     * @return string The decrypted data.
     * @throws RuntimeException If the decryption operation fails.
     */
    public function decrypt_data($data, $key, $salt)
    {
        $key = base64_decode($key);
        $salt = base64_decode($salt);

        // Derive the key using a Key Derivation Function
        $dervied_key = hash_pbkdf2('sha256', $key, $salt, Consts::getPbkdf2Iterations(), 0, true);

        $decoded_data = base64_decode($data);
        $iv_length = Consts::getIvBinLength();
        $iv = substr($decoded_data, 0, $iv_length);
        $tag = substr($decoded_data, $iv_length, Consts::getTagLength());
        $encrypted = substr($decoded_data, $iv_length + Consts::getTagLength());

        $decrypted = openssl_decrypt($encrypted, 'aes-256-GCM', $dervied_key, OPENSSL_RAW_DATA, $iv, $tag);

        if ($decrypted === false) {
            throw new RuntimeException('Retrieve RSA Private Key Decryption failed.');
        }

        return $decrypted;
    }
}
