<?php

use TCENVPHP\Modules\Constants\Core\Consts;

it('gets the correct values for the constants', function () {

    expect(Consts::getKey4096())->toBe(4096);
    expect(Consts::getIvBinLength())->toBe(16);
    expect(Consts::getIvBinGcmLength())->toBe(12);
    expect(Consts::getIvBinCbcLength())->toBe(16);
    expect(Consts::getTagLength())->toBe(16);
    expect(Consts::getSaltLength())->toBe(16);
    expect(Consts::getHLength())->toBe(64);
    expect(Consts::getRandHexLength())->toBe(90);
    expect(Consts::getRandByteLength())->toBe(32);
    expect(Consts::getHashLength())->toBe(64);
    expect(Consts::getPbkdf2Iterations())->toBe(1000000);
});
