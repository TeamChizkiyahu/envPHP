<?php

declare(strict_types=1);

namespace TCENVPHP\Auth;

use TCENVPHP\Modules\Constants\Core\Consts;
use TCENVPHP\Modules\Constants\Core\AnonConsts;

use TCENVPHP\Modules\Interface\Scrambler;
use TCENVPHP\Modules\Interface\VerifyPseudo;



/**
 * Class Gen
 *
 * This class provides methods for generating RSA key pairs and encryption keys.
 * 
 * This namespace is used to define classes related to authentication and encryption operations for the TCENVPHP application.
 *
 * @package TCENVPHP\Auth
 */
final class Gen
{
    /**
     * The instance of the Scrambler class used for data scrambling operations.
     *
     * @var Scrambler
     */
    private Scrambler $scrambler;

    /**
     * The instance of the VerifyPseudo class used to generate secure random bytes.
     *
     * @var VerifyPseudo
     */
    private VerifyPseudo $verifyPseudo;

    public function __construct()
    {
        $this->verifyPseudo = new VerifyPseudo(); //assuming VerifyPseudo doesn't have any dependencies
        $this->scrambler = new Scrambler(); //assuming Scrambler doesn't have any dependencies
    }

    /**
     * Generates an RSA key pair and encrypts it with AES-256-GCM.
     *
     * @param string $otp One-time password, base64 encoded.
     * @param string $salt Salt for the key derivation function, base64 encoded.
     * @return array Contains encrypted RSA key pair and a hash of encrypted tags and IV, scrambled with OTP.
     */
    public function generate_rsa_key_pair($otp, $salt)
    {
        // RSA init
        $rsa_config = array(
            "digest_alg" => "sha512",
            "private_key_bits" => Consts::getKey4096(),
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        $otp = base64_decode($otp);

        $salt = base64_decode($salt);


        $keyPair = openssl_pkey_new($rsa_config);
        openssl_pkey_export($keyPair, $private_key);

        $key_details  = openssl_pkey_get_details($keyPair);
        $public_key = $key_details["key"];

        // call auth credentials
        $derived_key = hash_pbkdf2('sha256', $otp, $salt, Consts::getPbkdf2Iterations(), 32, true);

        // randomness
        $iv_for_tags = random_bytes(Consts::getIvBinLength());
        $tag_iv = random_bytes(Consts::getIvBinLength());

        $pu_tag = random_bytes(Consts::getTagLength());
        $pv_tag = random_bytes(Consts::getTagLength());

        // encryption
        $encrypted_public_key = openssl_encrypt($public_key, 'AES-256-GCM', $derived_key, OPENSSL_RAW_DATA, $iv_for_tags, $pu_tag);     //public
        $encrypted_private_key = openssl_encrypt($private_key, 'AES-256-GCM', $derived_key, OPENSSL_RAW_DATA, $iv_for_tags, $pv_tag);       //private
        // tag encryptions
        $encrypted_pu_tag = openssl_encrypt($pu_tag, 'AES-256-CBC', $derived_key, OPENSSL_RAW_DATA, $tag_iv);
        $encrypted_pv_tag = openssl_encrypt($pv_tag, 'AES-256-CBC', $derived_key, OPENSSL_RAW_DATA, $tag_iv);

        //prepare
        $encrypted_pu_tag_length = strlen($encrypted_pu_tag);
        $encrypted_pv_tag_length = strlen($encrypted_pv_tag);

        // Combine, hash, and scramble the encrypted tags and IV
        $combined_tags_iv = $encrypted_pu_tag . $encrypted_pv_tag . $tag_iv . pack('N', $encrypted_pu_tag_length) . pack('N', $encrypted_pv_tag_length);
        $hashed_tags_iv = openssl_encrypt($combined_tags_iv, 'AES-256-CBC', $derived_key, OPENSSL_RAW_DATA, $iv_for_tags);
        $hashes = $hashed_tags_iv . $iv_for_tags;


        $beHashes = base64_encode($hashes);
        $shash = $this->scrambler->xor_scramble($beHashes, $otp);

        return array(
            'private_key' => $encrypted_private_key,
            'public_key' => $encrypted_public_key,
            'hashes' => $shash,
        );
    }

    /**
     * Generates an a random bytes as an encryption key through an abstract class constant.
     *
     * @return string The generated random bytes for an encryption key.
     */
    public function generate_encryption_key()
    {
        $random_bytes = $this->verifyPseudo->verifySecurePseudoRandomBytes((new AnonConsts())->getRand());
        return $random_bytes;
    }
}
