<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Constants\Core;


define('KEY_4096', 4096);
define('IV_BIN_LENGTH', 16);
define('IV_BIN_GCM_LENGTH', 12);
define('IV_BIN_CBC_LENGTH', 16);
define('TAG_LENGTH', 16);
define('SALT_LENGTH', 16);
define('H_LENGTH', 64);
define('RAND_HEX_LENGTH', 90);
define('RAND_BYTE_LENGTH', 32);
define('HASH_LENGTH', 64);
define('PBKDF2_ITERATIONS', 1000000);



/**
 * A collection of cryptographic related constants.
 *
 * This class contains constants related to cryptographic functions such as key lengths, salt lengths, and hash lengths.
 * This class uses the Singleton pattern, and thus can not be instantiated or cloned.
 * 
 * This namespace is used to define global constants and a singleton class for cryptographic functions. The define() is used
 * for compatibility with older versions of PHP, whereas using class constants with the const keyword inside a class.
 * 
 * Requires PHP 7.4 or later.
 *
 * @package TCENVPHP\Modules\Constants\Core
 */
final class Consts
{

    /**
     * The Consts constructor.
     *
     * Private to prevent instantiation.
     */    private function __construct()
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
     * Magic method to prevent unserialization of the class.
     *
     * @throws \Exception always
     */
    public function __wakeup()
    {
    }

    // class private constants

    private static $KEY_4096 = KEY_4096;
    private static $IV_BIN_LENGTH = IV_BIN_LENGTH;
    private static $IV_BIN_GCM_LENGTH = IV_BIN_GCM_LENGTH;
    private static $IV_BIN_CBC_LENGTH = IV_BIN_CBC_LENGTH;
    private static $TAG_LENGTH = TAG_LENGTH;
    private static $SALT_LENGTH = SALT_LENGTH;
    private static $H_LENGTH = H_LENGTH;
    private static $RAND_HEX_LENGTH = RAND_HEX_LENGTH;
    private static $RAND_BYTE_LENGTH = RAND_BYTE_LENGTH;
    private static $HASH_LENGTH = HASH_LENGTH;
    private static $PBKDF2_ITERATIONS = PBKDF2_ITERATIONS;


    /**
     * Get the constant value of KEY_4096.
     *
     * Default value is 4096.
     * 
     * @return int The value of KEY_4096.
     */
    public static function getKey4096()
    {
        return self::$KEY_4096;
    }

    /**
     * Get the constant value of IV_BIN_LENGTH.
     *
     * Default value is 16.
     * 
     * @return int The value of IV_BIN_LENGTH.
     */
    public static function getIvBinLength()
    {
        return self::$IV_BIN_LENGTH;
    }



    /**
     * Get the constant value of IV_BIN_GCM_LENGTH.
     *
     * Default value is 12.
     * 
     * @return int The value of IV_BIN_GCM_LENGTH.
     */
    public static function getIvBinGcmLength()
    {
        return self::$IV_BIN_GCM_LENGTH;
    }

    /**
     * Get the constant value of IV_BIN_CBC_LENGTH.
     *
     * Default value is 16.
     * 
     * @return int The value of IV_BIN_CBC_LENGTH.
     */
    public static function getIvBinCbcLength()
    {
        return self::$IV_BIN_CBC_LENGTH;
    }

    /**
     * Get the constant value of TAG_LENGTH.
     *
     * Default value is 16.
     * 
     * @return int The value of TAG_LENGTH.
     */
    public static function getTagLength()
    {
        return self::$TAG_LENGTH;
    }

    /**
     * Get the constant value of SALT_LENGTH.
     * 
     * Default value is 16.
     *
     * @return int The value of SALT_LENGTH.
     */
    public static function getSaltLength()
    {
        return self::$SALT_LENGTH;
    }

    /**
     * Get the constant value of H_LENGTH.
     *
     * Default value is 64.
     * 
     * @return int The value of H_LENGTH.
     */
    public static function getHLength()
    {
        return self::$H_LENGTH;
    }

    /**
     * Get the set constant value of RAND_HEX_LENGTH.
     * 
     * Default value set at 90
     * 
     * @return int The value of RAND_HEX_LENGTH.
     */
    public static function getRandHexLength()
    {
        return self::$RAND_HEX_LENGTH;
    }

    /**
     * Get the set constant value of RAND_BYTE_LENGTH.
     *
     * Default value set at 32
     * 
     * @return int The value of RAND_BYTE_LENGTH.
     */
    public static function getRandByteLength()
    {
        return self::$RAND_BYTE_LENGTH;
    }

    /**
     * Get the set constant value of HASH_LENGTH.
     *
     * Default value set at 64
     * 
     * @return int The value of HASH_LENGTH.
     */
    public static function getHashLength()
    {
        return self::$HASH_LENGTH;
    }

    /**
     * Get the set constant value of PBKDF2_ITERATIONS.
     * 
     * Default value set at 1,000,000
     *
     * @return int The value of PBKDF2_ITERATIONS.
     */
    public static function getPbkdf2Iterations()
    {
        return self::$PBKDF2_ITERATIONS;
    }
}
