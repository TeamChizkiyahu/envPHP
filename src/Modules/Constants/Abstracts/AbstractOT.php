<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Constants\Abstracts;

use TCENVPHP\Modules\Constants\Core\OT;


/**
 * Abstract class AbstractOT.
 *
 * This abstract class extends the OT class. Any class inheriting from this class will have access to the
 * functionalities provided by the OT class.
 * 
 * This namespace is used to define an abstract class that extends the functionality of the OT class.
 *
 * @package TCENVPHP\Modules\Constants\Abstracts
 */
abstract class AbstractOT extends OT
{
    /**
     * AbstractOT constructor.
     *
     * Calls the parent OT class constructor.
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Magic method triggered when unserializing an instance.
     *
     * Calls the parent OT class __wakeup method.
     */
    public function __wakeup()
    {
        parent::__wakeup();
    }
}
