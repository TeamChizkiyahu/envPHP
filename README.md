# envPHP - Powerful env Fortification

Use this library for simple and seamless redundancy in env secrets encryption.

A robust and distilled approach to encryption tactics that empowers innovation.

envPHP is designed to enhance security and improve data handling within a PHP application. It includes features for handling encrypted environment variables, generating one-time passwords (OTPs), and secure storage and retrieval of sensitive data. 

This module helps to protect application data and increase the overall robustness of security within the application. It takes advantage of PHP's built-in functions and some standard cryptographic practices to achieve its goal.


# Enhance the security of your PHP application with Zero-Dependency

Your go-to module for secure data handling. You gain access to a suite of powerful tools for managing encrypted environment variables, generating one-time passwords, and storing and retrieving data securely. 

By leveraging PHP's built-in functions and industry-standard cryptographic practices, envPHP enhances your application with tools to help secure data. It's the module that delivers peace of mind with a simple API.

Are you ready to elevate your PHP application security to the next level? Consider envPHP - the module designed to enhance keep your application data safe and secure. 

Try envPHP today and experience the difference of how simplified tools for robust security can make.

## Requirements

Use of envPHP:

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

To effectivly use envPHP

```php

    //// Setup env file with necessary encryption keys ////

    // Instantiate TinyEnvPHP
    $envPHP = new TinyEnvPHP();

    // Initialize Random OTP & Salt
    $key = $envPHP->initOtp();
    $otp = $key['votp'];
    $salt = $key['vsalt'];

    // Set key for hash value
    $hkey = 'hashed_id';
    // Obtain Hash value
    $hashed_id = (new EnvPHPTooling())->setHash($otp);
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

    



    //// Store secret in env *example* ////

    if (isset($_POST['secret']) && isset($_POST['secret_i'])) {

        // Retrieve encrypted key array value as a string
        $encryptedKeyArray = get_option('encryptedKeyArray');

        $envPHP = new TinyEnvPHP();

        /* 
            descramble and decrypt key string back into an array of the original values 
            given by initOtp() with hashed_id appended to the array via setHash()
            that were previously passed to secStore()
        */
        $key = $envPHP->secRecall($encryptedKeyArray);
        $otp = $key['votp'];
        $salt = $key['vsalt'];
        $hashed_id = $key['hashed_id'];

        // Verify the integrity of OTP with the Hash Value
        $hashVerify = (new EnvPHPTooling())->verifyHash($otp, $hashed_id);
        if ($hashVerify) {

            // prepare secrets to be stored in the env file
            $envStore = [
                'SECRET_API_KEY' => $post['secret'],
                'SECRET_API_KEY_I' => $post['secret_i'],
            ];

            // utilizes encrypted keys to encrypt the envStore secrets and store them persistently in the env file that was previously created via initEnvFile()
            global $root_dir;
            $envPHP->wInitEnv($root_dir, $envStore, $otp, $salt);
        }
    }
    




    //// Retrieve env values for use ////

    // Instantiate TinyEnvPHP
    $envPHP = new TinyEnvPHP();

    // Retrieve encrypted key array value as a string
    $encryptedKeyArray = get_option('encryptedKeyArray');

    // One approach to efficiently and securely decrypt the OTP, Salt, & Hash with descrambling and AES decryption 
    $key = $envPHP->secRecall($encryptedKeyArray);
    $otp = $key['votp'];
    $salt = $key['vsalt'];
    $hashed_id = $key['hashed_id'];

    // Verify the integrity of OTP with the Hash Value
    $hashVerify = (new EnvPHPTooling())->verifyHash($otp, $hashed_id);
    if ($hashVerify) {

        global $root_dir;
        // Retrieves an env secret and decrypts value
        $decryptedSecret = $envPHP->getInitEnvValue($root_dir, 'SECRET_API_KEY', $otp, $salt);
        $decryptedSecret_i = $envPHP->getInitEnvValue($root_dir, 'SECRET_API_KEY_I', $otp, $salt);

        $keyData = compact('decryptedSecret', 'decryptedSecret_i');

        // Return env secrets decrypted and ready for use as an array
        return $keyData;
    }
```

Please be aware, hash_pbkdf2 is used in this current implementation of envPHP, the value of required iterations is set to 1,000,000 by default and can be adjusted in Consts.php

## Contributing 
Please consider reporting issues, submitting pull requests, and/or providing feedback.

If you care for the work we do please consider reaching out to sponsor and support Chizkiyahu's approach to advancing the basics with simplicity for 

For any additional help or information, please refer to the github.


## License 
This project is licensed under the Artistic License 2.0