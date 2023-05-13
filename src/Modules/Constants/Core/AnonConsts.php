<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Constants\Core;

define('RAND_START_CONST', rand(90, 150));

use Exception;



/**
 * Class AnonConsts
 *
 * This class is responsible for managing two types of random number constants:
 * - A number randomly selected between 90 and 150 only when the script runs (RAND_START_CONST)
 * - A random number that is instantiated at the time of creating an instance of this class (RAND_CONST)
 * 
 * This namespace is used to define a singleton class for that handles random number generation with some constraints as a global constant. 
 * The define() is used for compatibility with older versions of PHP, whereas using class constants with the const keyword inside a class.
 * 
 * @package TCENVPHP\Modules\Constants\Core
 */
final class AnonConsts
{
    private $RAND_CONST;
    private $RAND_START_CONST;

    /**
     * AnonConsts constructor.
     *
     * Sets the values for RAND_CONST and RAND_START_CONST.
     */
    public function __construct()
    {
        $this->RAND_CONST = random_int(90, 150);
        $this->RAND_START_CONST = RAND_START_CONST;
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
     * @throws \Exception if a user tries to unserialize an instance of this class.
     */
    public function __wakeup()
    {
        throw new Exception("Cannot unserialize instance");
    }

    /**
     * Get the RAND_CONST value.
     *
     * @return int The value of RAND_CONST.
     */
    public function getRand()
    {
        return $this->RAND_CONST;
    }

    /**
     * Get the RAND_START_CONST value.
     *
     * @return int The value of RAND_START_CONST.
     */
    public function getStartRand()
    {
        return $this->RAND_START_CONST;
    }
}
