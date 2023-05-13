<?php

use TCENVPHP\Modules\Interface\VerifyPseudo;

it('generates secure random bytes', function () {
    $length = 16;

    $mockGenerator = Mockery::mock(VerifyPseudo::class);
    $mockGenerator->shouldReceive('verifySecurePseudoRandomBytes')
        ->once()
        ->with($length)
        ->andReturnUsing(function ($length) {
            $isSecure = true;
            return openssl_random_pseudo_bytes($length, $isSecure);
        });

    $bytes = $mockGenerator->verifySecurePseudoRandomBytes($length);

    expect($bytes)->toBeString();
    expect(strlen($bytes))->toBe($length);
});


it('throws an exception for insecure random bytes', function () {
    $length = 16;

    $mockGenerator = Mockery::mock(VerifyPseudo::class);
    $mockGenerator->shouldReceive('verifySecurePseudoRandomBytes')
        ->once()
        ->with($length)
        ->andThrow(new \RuntimeException('Unable to generate a cryptographically secure random bytes.'));

    expect(function () use ($mockGenerator, $length) {
        $mockGenerator->verifySecurePseudoRandomBytes($length);
    })->toThrow(new RuntimeException('Unable to generate a cryptographically secure random bytes.'));
});
