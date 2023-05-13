<?php

use TCENVPHP\Modules\Constants\Core\Consts;
use TCENVPHP\Modules\Constants\Core\AnonConsts;

use TCENVPHP\Modules\Constants\Core\OT;

it('generates a random OTP and salt', function () {
    $bytes = random_bytes((new AnonConsts())->getRand() + Consts::getSaltLength());
    $otp = bin2hex(substr($bytes, 0, (new AnonConsts())->getRand()));
    $salt = bin2hex(substr($bytes, (new AnonConsts())->getRand(), Consts::getSaltLength()));

    $random_bytes_mock = Mockery::mock('overload:' . 'random_bytes');
    $random_bytes_mock->shouldReceive('__invoke')->once()->with(
        (new AnonConsts())->getRand() + Consts::getSaltLength()
    )->andReturn($bytes);

    $ot_mock = Mockery::mock(OT::class);
    $ot_mock->shouldReceive('otp')->once()->andReturn($otp);
    $ot_mock->shouldReceive('sal')->once()->andReturn($salt);

    expect($ot_mock::otp())->toBe($otp);
    expect($ot_mock::sal())->toBe($salt);
});
