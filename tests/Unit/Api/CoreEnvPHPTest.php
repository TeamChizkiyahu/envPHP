<?php

use TCENVPHP\Modules\Constants\Core\AnonConsts;

use TCENVPHP\Modules\Interface\VerifyPseudo;
use TCENVPHP\Modules\Interface\Scrambler;

use TCENVPHP\Auth\Gen;

use TCENVPHP\Modules\Api\CoreEnvPHP;


it('creates a new .env file with the correct content', function () {
    $verifyPseudo = Mockery::mock(VerifyPseudo::class);
    $scrambler = Mockery::mock(Scrambler::class);
    $coreEnvPHP = new CoreEnvPHP($verifyPseudo, $scrambler);

    $tempDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid();
    mkdir($tempDirectory);
    $coreEnvPHP->setDirectoryIfOkay($directory);
    $filename = $directory . DIRECTORY_SEPARATOR . '.env';

    // Remove the file if it already exists
    if (file_exists($filename)) {
        unlink($filename);
    }

    $name = 'test';
    $otp = 'otp';
    $salt = 'salt';

    // Call the method under test
    $coreEnvPHP->initEnvFile($name, $otp, $salt, true);

    // Check that the file was created
    expect(file_exists($filename))->toBeTrue();

    // Check the file content
    $content = file_get_contents($filename);
    expect($content)->toContain($name . "_PU_KEY=");
    expect($content)->toContain($name . "_PV_KEY=");
    expect($content)->toContain($name . "_HASH=");
    expect($content)->toContain($name . "_SCRAM=");

    // Cleanup: remove the file
    unlink($filename);
    rmdir($tempDirectory);
})->group('CoreEnvPHP');





it('throws an exception when trying to set an invalid directory', function () {
    // Create mocks for the dependencies
    $verifyPseudo = Mockery::mock(VerifyPseudo::class);
    $scrambler = Mockery::mock(Scrambler::class);

    // Instantiate the class we're testing
    $coreEnvPHP = new CoreEnvPHP($verifyPseudo, $scrambler);

    // This directory doesn't exist, so this should throw an exception
    $invalidDirectory = '/path/to/nonexistent/directory';

    // We expect an InvalidArgumentException to be thrown
    expect(function () use ($coreEnvPHP, $invalidDirectory) {
        $coreEnvPHP->setDirectoryIfOkay($invalidDirectory);
    })->toThrow(InvalidArgumentException::class);
});
