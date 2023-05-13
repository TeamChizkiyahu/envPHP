<?php

declare(strict_types=1);

namespace TCENVPHP\Modules\Instruments;

/**
 * Class Memory
 *
 * This class provides a method for clearing variables from memory.
 *
 * @package TCENVPHP\Modules\Instruments
 */
final class Memory
{

    /**
     * Clear the given variables from memory.
     *
     * @param mixed ...$variables The variables to clear from memory.
     * @return void
     */
    public static function wipe(&...$variables)
    {
        foreach ($variables as &$variable) {
            $variable = null;
            unset($variable);
        }
        // Force garbage collection
        gc_collect_cycles();
    }
}
