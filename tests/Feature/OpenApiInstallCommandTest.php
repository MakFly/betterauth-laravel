<?php

declare(strict_types=1);

it('fails gracefully when api platform is not installed', function (): void {
    $this->artisan('betterauth:openapi-install --yes')
        ->expectsOutputToContain('API Platform is not installed')
        ->assertExitCode(1);
});
