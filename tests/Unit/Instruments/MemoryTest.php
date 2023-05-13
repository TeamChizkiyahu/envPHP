<?php

use TCENVPHP\Modules\Instruments\Memory;

it('wipes specified variables from memory', function () {
    $variable1 = 'test';
    $variable2 = 123;

    $initialMemory = memory_get_usage();
    expect($initialMemory)->toBeGreaterThan(0);

    Memory::wipe($variable1, $variable2);

    expect($variable1)->toBeNull();
    expect($variable2)->toBeNull();

    $finalMemory = memory_get_usage();
    expect($finalMemory)->toBeLessThan($initialMemory);
});
