<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Constants\Core;




/**
 * Abstract class for one-time-password (OTP) and salt generation.
 *
 * This class initializes and provides access to OTP and salt which are generated only once per run.
 * It uses the Singleton pattern to ensure these values are consistent throughout a single run.
 * 
 * This namespace is used to define an abstract class responsible for one-time-password (OTP) and salt generation.
 *
 * @package TCENVPHP\Modules\Constants\Core
 */
abstract class OT
{
    private static $hasRun = false;
    private static $otp;
    private static $salt;


    /**
     * The OT constructor.
     *
     * Protected to prevent instantiation.
     */
    protected function __construct()
    {
    }

    /**
     * Magic method to prevent cloning of the class.
     *
     * @throws \Exception always
     */
    private function __clone()
    {
    }

    /**
     * Magic method to reinitialize the class when unserialized.
     */
    public function __wakeup()
    {
        self::init();
    }

    /**
     * Initializes the class by generating the OTP and salt, if they haven't been generated yet.
     */
    public static function init()
    {
        if (!self::$hasRun) {
            // Your code that should only run once goes here

            self::$otp = self::generateOtp();
            self::$salt = self::generateSalt();

            self::$hasRun = true;
        }
    }

    /**
     * Generates a new OTP.
     *
     * @return string The generated OTP.
     */
    protected static function generateOtp()
    {
        return self::$otp = bin2hex(random_bytes((new AnonConsts())->getRand()));
    }

    /**
     * Generates a new salt.
     *
     * @return string The generated salt.
     */
    protected static function generateSalt()
    {
        return self::$salt = bin2hex(random_bytes(Consts::getSaltLength()));
    }

    /**
     * Retrieves the OTP, initializing the class if necessary.
     *
     * @return string The OTP.
     */
    public static function otp()
    {
        if (!self::$hasRun) {
            // Initialize the class if it hasn't been done yet
            self::init();
        }
        return self::$otp;
    }

    /**
     * Retrieves the salt, initializing the class if necessary.
     *
     * @return string The salt.
     */
    public static function sal()
    {
        if (!self::$hasRun) {
            // Initialize the class if it hasn't been done yet
            self::init();
        }
        return self::$salt;
    }
}
