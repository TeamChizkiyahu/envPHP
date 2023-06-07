# envPHP - Powerful Fortification

Use this library for simple and seamless redundancy in env secrets encryption.

A robust and distilled approach to encryption tactics that empowers innovation.

envPHP is designed to enhance security and improve data handling within a PHP application. It includes features for handling encrypted environment variables, generating one-time passwords (OTPs), and secure storage and retrieval of sensitive data. 

envPHP helps to protect application data and increase the overall robustness of security within the application. It takes advantage of PHP's built-in functions and some standard cryptographic practices to achieve its goal.


# Enhanced PHP application security

Gain access to a suite of powerful tools for managing encrypted environment variables, generating one-time passwords, and storing and retrieving data securely.

By leveraging PHP's built-in functions and industry-standard cryptographic practices, envPHP enhances your application with tools to help secure data with a simple API.

Try envPHP today and experience the difference of zero-dependency encryption of environment variables. 

## Requirements

- PHP >= 7.4

Some features of the library may not be compatible with earlier versions of PHP. Please check your PHP version before installing envPHP, to avoid any compatibility issues.

envPHP operates with files and directories within your system. Therefore, please ensure:

File Creation: In some cases, envPHP may need to create new files. Ensure PHP has file creation permissions in the necessary directories.

Read/Write Access: envPHP needs read and write access to the directory which will contain the .env file(s) for initializing and manipulating the environment file.

Server Configurations: If you're using envPHP in a web server context, ensure your server allows PHP to read and write files, and execute necessary system-level operations and has openSSL enabled.

Before starting, ensure these requirements are met to enjoy a smooth experience with envPHP.

## Installation

To install the envPHP, run the following command:

```bash
composer require teamchizkiyahu/envphp
```

## Usage 

To effectivly use envPHP:

```php

//// Setup env file with necessary encryption keys ////

// Instantiate TinyEnvPHP
use TCENVPHP\Modules\Api\TinyEnvPHP;

$envPHP = new TinyEnvPHP();

// Initialize Random OTP & Salt
$key = $envPHP->initOtp();
$otp = $key['votp'];
$salt = $key['vsalt'];

// Set key for hash value
$hkey = 'hashed_id';
// Obtain a Hash value of the OTP
$hashed_id = $envPHP->setHash($otp);
// Add to $key array
$key[$hkey] = $hashed_id;


/*
One approach to efficiently and securely prepare as a string 
the OTP, Salt, & Hash are scrambled and encrypted with AES 
for persistently storing the keys to access the encrypted env keys that are used for encryption of env secrets
*/
$encryptedKeyArray = $envPHP->secStore($key);
// One example to store the $key array
update_option('encryptedKeyArray', $encryptedKeyArray);

// Intialize env file with zero knowledge of encrypted RSA public and private keys, hash, and scramble key
global $root_dir;
$envPHP->initEnvFile($root_dir, $otp, $salt, true);
$envPHP->memoryWipe($key, $otp, $salt, $hkey, $hashed_id, $encryptedKeyArray);

    



//// Store secret in env *example* ////
use TCENVPHP\Modules\Api\TinyEnvPHP;

if (isset($_POST['secret']) && isset($_POST['secret_i'])) {

// Retrieve encrypted key array value as a string
$encryptedKeyArray = get_option('encryptedKeyArray');

$envPHP = new TinyEnvPHP();

/* 
Descramble and decrypt key string back into an array of the original values 
given by initOtp() with hashed_id appended to the array via setHash()
that were previously passed to secStore()
*/
$key = $envPHP->secRecall($encryptedKeyArray);
$otp = $key['votp'];
$salt = $key['vsalt'];
$hashed_id = $key['hashed_id'];

// Verify the integrity of OTP with the Hash Value that was generated with the otp
$hashVerify = $envPHP->verifyHash($otp, $hashed_id);
if ($hashVerify) {

    // prepare secrets to be stored in the env file
    $envStore = [
            'SECRET_API_KEY' => $post['secret'],
            'SECRET_API_KEY_I' => $post['secret_i'],
        ];

    // utilizes encrypted keys to encrypt the envStore secrets and store them persistently in the env file that was previously created via initEnvFile()
    global $root_dir;
    $envPHP->wInitEnv($root_dir, $envStore, $otp, $salt);
    $envPHP->memoryWipe($envStore);
    }
    $envPHP->memoryWipe($post['secret'],  $post['secret_i'], $encryptedKeyArray, $key, $otp, $salt, $hashed_id, $hashVerify);
}
    




//// Retrieve env values for use ////
use TCENVPHP\Modules\Api\TinyEnvPHP;

// Instantiate TinyEnvPHP
$envPHP = new TinyEnvPHP();

// Retrieve encrypted key array value as a string
$encryptedKeyArray = get_option('encryptedKeyArray');

// One approach to efficiently and securely decrypt the OTP, Salt, & Hash with descrambling and AES decryption 
$key = $envPHP->secRecall($encryptedKeyArray);
$otp = $key['votp'];
$salt = $key['vsalt'];
$hashed_id = $key['hashed_id'];

// Verify the integrity of OTP with the Hash Value that was generated with the otp
$hashVerify = $envPHP->verifyHash($otp, $hashed_id);
if ($hashVerify) {

    global $root_dir;
    // Retrieves an env secret and decrypts value
    $decryptedSecret = $envPHP->getInitEnvValue($root_dir, 'SECRET_API_KEY', $otp, $salt);
    $decryptedSecret_i = $envPHP->getInitEnvValue($root_dir, 'SECRET_API_KEY_I', $otp, $salt);

    $keyData = compact('decryptedSecret', 'decryptedSecret_i');

    $envPHP->memoryWipe($decryptedSecret, $decryptedSecret_i);

    // Return env secrets decrypted and ready for use as an array
    return $keyData;
}

$envPHP->memoryWipe($encryptedKeyArray, $key, $otp, $salt, $hashed_id, $hashVerify);

```

Please be aware, hash_pbkdf2 is used in this current implementation of envPHP, the value of required iterations is set to 1,000,000 by default and can be adjusted in Consts script.


## Contributing 
Please consider reporting issues, submitting pull requests, contributing to discussions, and/or providing feedback on github.

If you care for the work we do please consider reaching out to sponsor us.

Please consider supporting our approach to advancing the basics with simplicity for achieving the next generation of agnostic and framework friendly package architecture that distills vision, creativity, and practicallty.

We hope to foster and advocate for tools that strenghens community locally and remotely.

We aim to be a non-profit collective that seeks to empower app developers in local communities and remotely distributed communities. 

## License 
This project is licensed under the Artistic License 2.0