<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Api;

use TCENVPHP\Modules\Interface\Scrambler;

use TCENVPHP\Auth\Masters;
use TCENVPHP\Auth\Gen;
use TCENVPHP\Auth\Rsa;

use InvalidArgumentException;
use RuntimeException;

/**
 * Class CoreEnvPHP
 *
 * CoreEnvPHP manages encrypted environment variables for PHP applications.
 * This class provides methods for setting and getting encrypted environment variables,
 * and for writing new ones to the environment file.
 * The encryption uses RSA public/private key pairs, combined with a one-time pad and a salt.
 *
 * @package TCENVPHP\Modules\Api
 */
final class CoreEnvPHP
{
    private $directory;
    private $keyPair = null;
    private $hasRun = false;


    /**
     * Generate an RSA key pair if not already done.
     *
     * @param string $otp The one-time pad to be used for RSA key pair generation.
     * @param string $salt The salt value to be used for RSA key pair generation.
     * @return array Returns the generated RSA key pair.
     */
    private function getKeyPair(string $otp, string $sal): array
    {
        if (!$this->hasRun) {
            $this->keyPair = (new Gen())->generate_rsa_key_pair($otp, $sal);
            $this->hasRun = true;
        }
        return $this->keyPair;
    }

    /**
     * Validate and set the directory for the environment file.
     *
     * @param string $directory The directory where the environment file is located.
     * @throws InvalidArgumentException If the provided directory is invalid or not writable.
     */
    public function setDirectoryIfOkay($directory)
    {
        if (!is_dir($directory) || !is_writable($directory)) {
            throw new InvalidArgumentException("Invalid directory or not writable: {$directory}");
        }

        $this->directory = $directory;
    }


    /**
     * Initialize the environment file with encryption keys and hashes.
     *
     * @param string $name The prefix for the environment variables related to encryption keys and hashes.
     * @param string $otp The one-time pad to be used for RSA key pair generation.
     * @param string $salt The salt value to be used for RSA key pair generation.
     * @param bool $overwrite Whether to overwrite the existing file.
     * 
     * @throws RuntimeException If the directory has not been set or if file operations fail.
     */
    public function initEnvFile($name, $otp, $salt, $overwrite = false)
    {
        if ($this->directory === null) {
            throw new RuntimeException("Directory not set. Use Env::setDirectory() to set the directory.");
        }
        // Set the filename
        $filename = $this->directory . DIRECTORY_SEPARATOR . '.env';

        $keyPair = $this->getKeyPair($otp, $salt);
        $pu_key = $keyPair['public_key'];
        $pv_key = $keyPair['private_key'];
        $hash = $keyPair['hashes'];
        $pubKey = (new Masters())->get_rsa_public($pu_key, $hash, $otp, $salt);
        $randKey = (new Gen())->generate_encryption_key();
        $encScram = (new Rsa())->rsa_encrypt_data($randKey, $pubKey, $otp);
        $content = '';

        // Append the public key, private key, and hashes to the content string
        $content .= $name . "_" . "PU_KEY=" . base64_encode(base64_decode(bin2hex($pu_key))) . "\n";
        $content .= $name . "_" . "PV_KEY=" . base64_encode(base64_decode(bin2hex($pv_key))) . "\n";
        $content .= $name . "_" . "HASH=" . base64_encode($hash) . "\n";
        $content .= $name . "_" . "SCRAM=" . bin2hex($encScram) . "\n";


        // If the file doesn't exist, create it with the exclusive lock and write the content
        if (!file_exists($filename)) {
            $file = @fopen($filename, 'x');
            if ($file === false) {
                throw new RuntimeException("Failed to create the file: {$filename}");
            }
        } else {
            // Choose the file opening mode based on the $overwrite flag
            $mode = $overwrite ? 'w' : 'a';

            // Open the file with the selected mode
            $file = @fopen($filename, $mode);
            if ($file === false) {
                throw new RuntimeException("Failed to open the file: {$filename}");
            }
        }
        // Write the content to the file
        if (fwrite($file, $content) === false) {
            throw new RuntimeException("Failed to write to the file: {$filename}");
        }
        // Close the file
        fclose($file);

        // Change the file permissions to 600 (owner read and write)
        if (!chmod($filename, 0600)) {
            throw new RuntimeException("Failed to set permissions for the file: {$filename}");
        }
    }

    /**
     * Write key-value pairs to the environment file in an encrypted and scrambled format.
     * The method also handles updating existing values and encrypting new ones.
     * 
     * @param string $directory The directory where the environment file is located.
     * @param string $name The prefix for the environment variables related to encryption keys and hashes.
     * @param array  $keyStore An associative array of key-value pairs to be written to the environment file.
     * @param string $otp The one-time pad to be used for RSA key pair generation and decryption.
     * @param string $salt The salt value to be used for RSA key pair generation.
     * @throws RuntimeException If file operations fail.
     */
    public function wEnv($directory, $name, array $keyStore, $otp, $salt)
    {
        // Set the filename
        $filename = $directory . DIRECTORY_SEPARATOR . '.env';

        // Load the public key, private key, and hashes from the file
        $envStore = $this->callEncryptedEnv($directory);

        $pubHK = hex2bin(base64_encode(base64_decode($envStore[$name . '_PU_KEY'])));
        $privHK = hex2bin(base64_encode(base64_decode($envStore[$name . '_PV_KEY'])));
        $hash = base64_decode($envStore[$name . '_HASH']);
        $encRandKey = hex2bin($envStore[$name . '_SCRAM']);

        $mastersInstance = new Masters();
        $rsaInstance = new Rsa();
        $scramblerInstance = new Scrambler();

        $pubKey = $mastersInstance->get_rsa_public($pubHK, $hash, $otp, $salt);
        $priKey = $mastersInstance->get_rsa_private($privHK, $hash, $otp, $salt);
        $scramKey = $rsaInstance->rsa_decrypt_data($encRandKey, $priKey, $otp);


        // Read the existing content from the file
        $existingContent = @file_get_contents($filename);
        if ($existingContent === false) {
            throw new RuntimeException("Failed to read the file: {$filename}");
        }

        // Create an associative array from the existing content
        $existingContentArray = array();
        $lines = explode("\n", $existingContent);
        foreach ($lines as $line) {
            $explodedLine = explode('=', $line, 2);

            // Check if the exploded line has two elements (key and value)
            if (count($explodedLine) === 2) {
                list($key, $value) = $explodedLine;
                $existingContentArray[$key] = $value;
            }
        }

        // Iterate through the key store and scramble the values
        foreach ($keyStore as $key => $value) {
            $value = $rsaInstance->rsa_encrypt_data($value, $pubKey, $otp);
            $value = base64_encode($value);
            $scrambledValue = $scramblerInstance->xor_scramble($value, $scramKey);
            $hexScrambledValue = bin2hex($scrambledValue);

            // Check for duplicates and overwrite if necessary
            $existingContentArray[$key] = $hexScrambledValue;
        }

        // Convert the updated content array back to a string
        $content = '';
        foreach ($existingContentArray as $key => $value) {
            $content .= "{$key}={$value}\n";
        }

        // Open the file in write mode
        $file = @fopen($filename, 'w');

        if ($file === false) {
            throw new RuntimeException("Failed to open the file: {$filename}");
        }

        // Write the content to the file and close it
        fwrite($file, $content);
        fclose($file);

        // Change the file permissions to 600 (owner read and write only)
        if (!chmod($filename, 0600)) {
            throw new RuntimeException("Failed to set permissions for the file: {$filename}");
        }
    }

    /**
     * Retrieve the decrypted value of an environment variable.
     *
     * @param string $directory The directory where the environment file is located.
     * @param string $name The prefix for the environment variables related to encryption keys and hashes.
     * @param string $keyName The key of the environment variable to be retrieved.
     * @param string $otp The one-time pad to be used for RSA key pair generation and decryption.
     * @param string $salt The salt value to be used for RSA key pair generation.
     * @return string|null The decrypted value of the environment variable, or null if the key is not found.
     * 
     * @throws InvalidArgumentException If the environment file is not found or not readable.
     */
    public function getEnvValue($directory, $name, $keyName, $otp, $salt)
    {

        // Set the filename
        $filename = $directory . DIRECTORY_SEPARATOR . '.env';

        // Check if the file exists and is readable
        if (!is_file($filename) || !is_readable($filename)) {
            throw new InvalidArgumentException("File not found or not readable: {$filename}");
        }

        // Read the content of the file
        $content = file_get_contents($filename);


        // Load the public key, private key, and hashes from the file
        $envStore = $this->callEncryptedEnv($directory);

        $privHK = hex2bin(base64_encode(base64_decode($envStore[$name . '_PV_KEY'])));
        $hash = base64_decode($envStore[$name . '_HASH']);
        $encRandKey = hex2bin($envStore[$name . '_SCRAM']);

        $rsaInstance = new Rsa();
        $scramblerInstance = new Scrambler();


        $priKey =  (new Masters())->get_rsa_private($privHK, $hash, $otp, $salt);
        $scramKey = $rsaInstance->rsa_decrypt_data($encRandKey, $priKey, $otp);

        // Find the value for the given key
        $pattern = '/^' . preg_quote($keyName, '/') . '=(.*)$/m';
        if (preg_match($pattern, $content, $matches)) {
            $scrambledValue = $matches[1];
            $binScrambledValue = hex2bin($scrambledValue);
            $unscrambledValue =  $scramblerInstance->xor_scramble($binScrambledValue, $scramKey);
            $base64DecodedValue = base64_decode($unscrambledValue);
            $decryptedValue = $rsaInstance->rsa_decrypt_data($base64DecodedValue, $priKey, $otp);
            return $decryptedValue;
        }

        // Return null if the key is not found
        return null;
    }

    /**
     * Reads the content of the encrypted environment file and returns the key-value pairs.
     *
     * The environment file is expected to be located in the provided directory and named '.env'.
     * It reads the file line by line and for each line, it separates the key and value by the '=' character and
     * adds them to the returned array.
     *
     * @param string $directory The directory where the encrypted environment file is located.
     * @return array The key-value pairs from the environment file.
     * 
     * @throws InvalidArgumentException if the file does not exist or is not readable.
     */
    public function callEncryptedEnv($directory)
    {
        // Set the filename
        $filename = $directory . DIRECTORY_SEPARATOR . '.env';

        // Check if the file exists and is readable
        if (!is_file($filename) || !is_readable($filename)) {
            throw new InvalidArgumentException("File not found or not readable: {$filename}");
        }

        // Read the content of the file
        $content = file_get_contents($filename);

        // Split the content by lines
        $lines = explode("\n", $content);

        // Initialize the key store array
        $keyStore = [];

        // Iterate through each line, and add the key-value pair to the key store array
        foreach ($lines as $line) {
            // Skip empty lines
            if (trim($line) === '') {
                continue;
            }

            // Split the line into key and value
            list($key, $value) = explode('=', $line, 2);

            // Add the key-value pair to the key store array
            $keyStore[$key] = $value;
        }

        return $keyStore;
    }
}
