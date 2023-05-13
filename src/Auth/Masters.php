<?php

declare(strict_types=1);

namespace TCENVPHP\Auth;

use TCENVPHP\Modules\Constants\Core\Consts;
use TCENVPHP\Modules\Interface\Scrambler;

use RuntimeException;


/**
 * Class Masters
 *
 * This class provides methods for retrieving RSA public and private keys by decrypting them with AES-256-GCM.
 * 
 * This namespace is used to define classes related to authentication and encryption operations for the TCENVPHP application.
 *
 * @package TCENVPHP\Auth
 */
final class Masters
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
     * Retrieves the RSA public key by decrypting the encrypted key with AES-256-GCM.
     *
     * @param string $encrypted_key The encrypted RSA public key.
     * @param string $hashes The hash of the encrypted tags and IV, scrambled with OTP.
     * @param string $otp One-time password, base64 encoded.
     * @param string $salt Salt for the key derivation function, base64 encoded.
     * @return string The decrypted RSA public key.
     *
     * @throws RuntimeException If decryption fails.
     */
    public function get_rsa_public($encrypted_key, $hashes, $otp, $salt)
    {
        $otp = base64_decode($otp);
        $salt = base64_decode($salt);

        // auth
        $derived_key = hash_pbkdf2('sha256', $otp, $salt, Consts::getPbkdf2Iterations(), 32, true);

        $scramHashes = $this->scrambler->xor_scramble($hashes, $otp);
        $deHash = base64_decode($scramHashes);

        $iv_length = Consts::getIvBinLength();
        $deHash_length = strlen($deHash);
        $iv = substr($deHash, -Consts::getIvBinLength());
        $hashed_tags_iv_length = $deHash_length - $iv_length;
        $hashed_tags_iv = substr($deHash, 0, $hashed_tags_iv_length);

        // Extract the original encrypted tags and IV and the lengths of the encrypted tags
        $decrypted_combined_tags_iv = openssl_decrypt($hashed_tags_iv, 'AES-256-CBC', $derived_key, OPENSSL_RAW_DATA, $iv);
        if ($decrypted_combined_tags_iv === false) {
            throw new RuntimeException("Failed to decrypt combined tags iv: " . openssl_error_string());
        }
        $encrypted_pu_tag_length = unpack('N', substr($decrypted_combined_tags_iv, -8, 4))[1];
        $encrypted_pv_tag_length = unpack('N', substr($decrypted_combined_tags_iv, -4))[1];

        $encrypted_pu_tag = substr($decrypted_combined_tags_iv, 0, $encrypted_pu_tag_length);
        $tag_iv = substr($decrypted_combined_tags_iv, $encrypted_pu_tag_length + $encrypted_pv_tag_length, Consts::getIvBinLength());

        // Decrypt the key and tags using derived encryption
        $pu_tag = openssl_decrypt($encrypted_pu_tag, 'AES-256-CBC', $derived_key, OPENSSL_RAW_DATA, $tag_iv);
        $decrypted_key = openssl_decrypt($encrypted_key, 'AES-256-GCM', $derived_key, OPENSSL_RAW_DATA, $iv, $pu_tag);

        return $decrypted_key;
    }

    /**
     * Retrieves the RSA private key by decrypting the encrypted key with AES-256-GCM.
     *
     * @param string $encrypted_key The encrypted RSA private key.
     * @param string $hashes The hash of the encrypted tags and IV, scrambled with OTP.
     * @param string $otp One-time password, base64 encoded.
     * @param string $salt Salt for the key derivation function, base64 encoded.
     * @return string The decrypted RSA private key.
     *
     * @throws RuntimeException If decryption fails.
     */
    public function get_rsa_private($encrypted_key, $hashes, $otp, $salt)
    {

        $otp = base64_decode($otp);
        $salt = base64_decode($salt);

        // auth
        $derived_key = hash_pbkdf2('sha256', $otp, $salt, Consts::getPbkdf2Iterations(), 32, true);


        // descramble, iv, tags
        $rhashes = $this->scrambler->xor_scramble($hashes, $otp);
        $rhashes = base64_decode($rhashes);

        $iv = substr($rhashes, -Consts::getIvBinLength());
        $hashed_tags_iv = substr($rhashes, 0, -Consts::getIvBinLength());

        // Extract the original encrypted tags and IV and the lengths of the encrypted tags
        $decrypted_combined_tags_iv = openssl_decrypt($hashed_tags_iv, 'AES-256-CBC', $derived_key, OPENSSL_RAW_DATA, $iv);
        $encrypted_pu_tag_length = unpack('N', substr($decrypted_combined_tags_iv, -8, 4))[1];
        $encrypted_pv_tag_length = unpack('N', substr($decrypted_combined_tags_iv, -4))[1];

        $encrypted_pv_tag = substr($decrypted_combined_tags_iv, $encrypted_pu_tag_length, $encrypted_pv_tag_length);
        $tag_iv = substr($decrypted_combined_tags_iv, $encrypted_pu_tag_length + $encrypted_pv_tag_length,  Consts::getIvBinLength());

        // Decrypt the key and the tags using the derived encryption key
        $pv_tag = openssl_decrypt($encrypted_pv_tag, 'AES-256-CBC', $derived_key, OPENSSL_RAW_DATA, $tag_iv);
        $decrypted_key = openssl_decrypt($encrypted_key, 'AES-256-GCM', $derived_key, OPENSSL_RAW_DATA, $iv, $pv_tag);

        if ($decrypted_key === false) {
            throw new RuntimeException('Retrieve RSA Private Key Decryption failed.');
        }

        return $decrypted_key;
    }
}
