<?php

use TCENVPHP\Modules\Constants\Core\AnonConsts;

it('should return a defined constant that does not match the constructor RAND_CONST', function () {
    $constObject = new AnonConsts();
    expect($constObject->getRand())->not->toBe(RAND_START_CONST);
});


it('should return different numbers for two instances', function () {
    $firstInstance = new AnonConsts();
    $secondInstance = new AnonConsts();

    $firstRand = $firstInstance->getRand();
    $secondRand = $secondInstance->getRand();

    expect($firstRand)->not->toBe($secondRand);
});

it('should not allow cloning', function () {
    $constObject = new AnonConsts();

    expect(function () use ($constObject) {
        clone $constObject;
    })->toThrow(Error::class);
});

it('should return at least a % of the values are unique given random restriction between 90 to 150 over multiple instances', function () {
    $randValues = [];
    for ($i = 0; $i < 1000; $i++) {
        $instance = new AnonConsts();
        $randValues[] = $instance->getRand();
    }

    // Count the unique values in the array. 
    // If the function is truly random, we'd expect most, if not all, values to be unique
    $uniqueValues = array_unique($randValues);

    $ratio = count($uniqueValues) / count($randValues);
    // Expect that at least 60% of the values are unique given random restriction between 90 to 150
    expect($ratio)->toBeGreaterThan(0.060);
});

it('should return a uniform distribution over multiple instances within a given % deviation', function () {
    $randValues = [];
    for ($i = 0; $i < 100000; $i++) { // increase the number of trials
        $instance = new AnonConsts();
        $randValues[] = $instance->getRand();
    }

    $valueCounts = array_count_values($randValues);
    $averageCount = array_sum($valueCounts) / count($valueCounts);

    // Check if each value is generated about the same number of times
    foreach ($valueCounts as $count) {
        // We allow larger deviation from the average due to randomness
        expect($count)->toBeGreaterThan($averageCount * 0.5); // 50% deviation
        expect($count)->toBeLessThan($averageCount * 1.5); // 50% deviation
    }
});

it('should not allow unserializing', function () {
    $constObject = new AnonConsts();

    expect(function () use ($constObject) {
        unserialize(serialize($constObject));
    })->toThrow(Exception::class);
});
