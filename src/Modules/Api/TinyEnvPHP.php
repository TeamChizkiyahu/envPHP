<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Api;

use TCENVPHP\Modules\Constants\Core\AnonConsts;
use TCENVPHP\Modules\Constants\Core\Consts;

use TCENVPHP\Modules\Constants\Abstracts\AbstractOT;

use TCENVPHP\Modules\Interface\Scrambler;

use TCENVPHP\Modules\Instruments\EnvPHPTooling;
use TCENVPHP\Modules\Instruments\Memory;

use TCENVPHP\Auth\Aes;


/**
 * Class TinyEnvPHP
 * 
 * This class provides functionality to initialize and manage environment files. 
 * It also includes secure storage and retrieval of data.
 *
 * @package TCENVPHP\Modules\Api
 */
class TinyEnvPHP
{

    /**
     * Initializes and retrieves a new OTP and Salt value pair.
     *
     * This function generates a new OTP and Salt value using the OT class's otp and sal methods.
     * It returns an associative array containing the generated OTP and Salt values.
     *
     * @return array An associative array containing the new OTP and Salt values, with keys 'votp' and 'vsalt'.
     */
    public function initOtp()
    {
        $otOtp = AbstractOT::otp();
        $otSalt = AbstractOT::sal();

        $otBeOtp = base64_encode($otOtp);
        $saBeSalt = base64_encode($otSalt);

        return array(
            'votp' => $otBeOtp,
            'vsalt' => $saBeSalt,
        );
    }

    /**
     * Initializes an environment file.
     *
     * @param string $directory The directory to create the environment file in.
     * @param string $otp The OTP for initializing the environment file.
     * @param string $salt The Salt for initializing the environment file.
     * @param string $name The name of the environment file, defaults to 'INIT'.
     */
    public function initEnvFile($directory, $otp, $salt, $name)
    {
        $envFile = new CoreEnvPHP();
        $envFile->setDirectoryIfOkay($directory);
        $name = 'INIT';

        $envFile->InitEnvFile($name, $otp, $salt, true);
    }



    /**
     * Appends a new key-value pair to the existing dynamic key store in the environment file.
     *
     * @param string $directory The directory where the environment file is located.
     * @param array  $addedKeyStore An associative array containing the new key-value pairs to be added.
     * @param string $otp The OTP for writing to the environment file.
     * @param string $salt The Salt for writing to the environment file.
     */
    public function wInitEnv($directory, $addedKeyStore, $otp, $salt)
    {
        $envFile = new CoreEnvPHP();
        $name = 'INIT';
        // Append the updated key store to initEnv file
        $envFile->wEnv($directory, $name, $addedKeyStore, $otp, $salt);
    }

    /**
     * Retrieves a value from the initial environment file given its key.
     *
     * @param string $directory The directory where the environment file is located.
     * @param string $keyName The key of the value to retrieve.
     * @param string $otp The OTP for reading the environment file.
     * @param string $salt The Salt for reading the environment file.
     * @return mixed The value associated with the provided key.
     */
    public function getInitEnvValue($directory, $keyName, $otp, $salt)
    {
        $envFile = new CoreEnvPHP();
        $name = 'INIT';
        return $envFile->getEnvValue($directory, $name, $keyName, $otp, $salt);
    }

    /**
     * Retrieves a value from an environment file given its key.
     *
     * @param string $directory The directory where the environment file is located.
     * @param string $name The name of the environment file.
     * @param string $keyName The key of the value to retrieve.
     * @param string $otp The OTP for reading the environment file.
     * @param string $salt The Salt for reading the environment file.
     * @return mixed The value associated with the provided key.
     */
    public function getEnvValue($directory, $name, $keyName, $otp, $salt)
    {
        $envFile = new CoreEnvPHP();
        return $envFile->getEnvValue($directory, $name, $keyName, $otp, $salt);
    }

    /**
     * Loads the environment file.
     *
     * @param string $directory The directory where the environment file is located.
     * @return mixed The loaded environment file.
     */
    public function loadEnv($directory)
    {
        $envFile = new CoreEnvPHP();
        return $envFile->callEncryptedEnv($directory);
    }


    /**
     * Stores data securely.
     *
     * The data is encrypted and combined into a single string which is then scrambled.
     *
     * @param mixed ...$data Data to be stored securely. Multiple parameters can be provided.
     * @return string The scrambled and encoded data.
     */
    public function secStore(...$data)
    {
        $key = bin2hex(random_bytes((new AnonConsts())->getRand()));
        $rand = bin2hex(random_bytes((new AnonConsts())->getRand()));
        $salt = bin2hex(random_bytes(Consts::getSaltLength()));

        $dervied_key = hash_pbkdf2('sha256', $rand, $salt, Consts::getPbkdf2Iterations(), 0, true);

        $aes = new Aes();
        $scramblerInstance = new Scrambler();

        // Combine all key-value pairs and append the key
        $combined_data = '';
        foreach ($data as $data_array) {
            foreach ($data_array as $data_key => $data_value) {
                $combined_data .= $data_key . ':' . $aes->encrypt_data($data_value, $dervied_key, $salt) . ';';
            }
        }
        $combined_data .= $rand . $salt;

        // Prepend the key length to the combined_data
        $combined_data = strlen($key) . '|' . strlen($rand) . '|' . strlen($salt) . '|' .  $combined_data;

        // Base encode with base64_encode
        $encoded_data = base64_encode($combined_data);

        // Apply Scrambler::xor_scramble and return
        $scram = $scramblerInstance->xor_scramble($encoded_data, $key);

        $prepStore = bin2hex($scram) . $key .  '|' . strlen($key);

        return base64_encode($prepStore);
    }

    /**
     * Recalls data that was securely stored using secStore method.
     *
     * The scrambled data is base64 decoded, then the key and its length are extracted from the end of the decoded data.
     * The data is then descrambled using the xor_scramble method of the Scrambler class.
     * Next, the descrambled data is base64 decoded, and the key length, random value length, and salt length are extracted.
     * The random value and salt are extracted from the end of the combined data.
     * A key is derived using the random value and salt.
     * The combined data is split into key-value pairs by the ';' delimiter, and the values are decrypted.
     * The decrypted key-value pairs are added to the returned array.
     *
     * @param string $scrambled_data The data that was scrambled and encoded by the secStore method.
     * @return array The retrieved key-value pairs from the scrambled data.
     */
    public function secRecall($scrambled_data)
    {
        $scrambled_data = base64_decode($scrambled_data);
        // Extract the key and its length from the end of the scrambled_data
        list($scrambled_data, $key_length) = explode('|', $scrambled_data);
        $key = substr($scrambled_data, -$key_length);


        $scrambled_data = substr($scrambled_data, 0, -$key_length);

        $scramblerInstance = new Scrambler();

        // Apply Scrambler::xor_scramble to descramble the data
        $descrambled_data = $scramblerInstance->xor_scramble(hex2bin($scrambled_data), $key);


        // Base64 decode the descrambled_data
        $descrambled_data = base64_decode($descrambled_data);

        // Extract the key length, random value length, and salt length
        list($key_length, $rand_length, $salt_length, $combined_data) = explode('|', $descrambled_data, 4);

        // Extract the random value and the salt from the end of the combined_data
        $rand = substr($combined_data, - ($rand_length + $salt_length), intval($rand_length)); // Fixed line


        $salt = substr($combined_data, -$salt_length);

        $combined_data = substr($combined_data, 0, - ($rand_length + $salt_length));


        // Derive the key using the random value and salt
        $derived_key = hash_pbkdf2('sha256', $rand, $salt, Consts::getPbkdf2Iterations(), 0, true);


        // Split the combined_data using the delimiters
        $key_value_pairs = explode(';', $combined_data);
        $retrieved_data = [];

        $aes = new Aes();

        // Decrypt the values and reconstruct the array
        foreach ($key_value_pairs as $key_value_pair) {
            if (strpos($key_value_pair, ':') !== false) {
                list($pair_key, $pair_value) = explode(':', $key_value_pair);
                $retrieved_data[$pair_key] = $aes->decrypt_data($pair_value, $derived_key, $salt);
            }
        }

        return $retrieved_data;
    }


    public function setHash($otp)
    {
        $hashed_id = (new EnvPHPTooling())->setHash($otp);
        return $hashed_id;
    }


    public function verifyHash($otp, $hashed_id)
    {
        $hashVerify = (new EnvPHPTooling())->verifyHash($otp, $hashed_id);
        return $hashVerify;
    }


    public function memoryWipe(&...$variables)
    {
        (new Memory())->wipe($variables);
    }


    public function startTinyEnv($root_dir)
    {
        $key = $this->initOtp();
        $otp = $key['votp'];
        $salt = $key['vsalt'];

        // Set key for hash value
        $hkey = 'hashed_id';

        // Obtain a Hash value of the OTP
        $hashed_id = $this->setHash($otp);

        // Add to $key array
        $key[$hkey] = $hashed_id;
        $encryptedKeyArray = $this->secStore($key);
        $this->initEnvFile($root_dir, $otp, $salt, true);
        $this->memoryWipe($key, $otp, $salt, $hkey, $hashed_id);

        return $encryptedKeyArray;
    }

    /* prepare secrets to be stored in the env file
        ie:
        $envStore = [
                'SECRET_API_KEY' => $post['secret'],
                'SECRET_API_KEY_I' => $post['secret_i'],
            ];
    */
    public function storeTinyEnv($encryptedKeyArray, $root_dir, $envStore)
    {
        $key = $this->secRecall($encryptedKeyArray);
        $otp = $key['votp'];
        $salt = $key['vsalt'];
        $hashed_id = $key['hashed_id'];

        $hashVerify = $this->verifyHash($otp, $hashed_id);
        if ($hashVerify) {

            $this->wInitEnv($root_dir, $envStore, $otp, $salt);
            $this->memoryWipe($envStore);
        }
        $this->memoryWipe($encryptedKeyArray, $key, $otp, $salt, $hashed_id, $hashVerify);
    }

    public function getTinyEnv($encryptedKeyArray, $root_dir, $env_name)
    {
        $key = $this->secRecall($encryptedKeyArray);
        $otp = $key['votp'];
        $salt = $key['vsalt'];
        $hashed_id = $key['hashed_id'];

        $hashVerify = $this->verifyHash($otp, $hashed_id);
        if ($hashVerify) {
            $decryptedSecret = $this->getInitEnvValue($root_dir, $env_name, $otp, $salt);

            $this->memoryWipe($encryptedKeyArray, $key, $otp, $salt, $hashed_id, $hashVerify);

            return $decryptedSecret;
        }
    }
}
