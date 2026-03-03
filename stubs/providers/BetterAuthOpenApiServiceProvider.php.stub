<?php

declare(strict_types=1);

namespace App\Providers;

use ApiPlatform\OpenApi\Factory\OpenApiFactoryInterface;
use ApiPlatform\OpenApi\Command\OpenApiCommand;
use App\OpenApi\BetterAuthOpenApiFactory;
use Illuminate\Support\ServiceProvider;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

class BetterAuthOpenApiServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->extend(OpenApiFactoryInterface::class, function (OpenApiFactoryInterface $factory): OpenApiFactoryInterface {
            return new BetterAuthOpenApiFactory($factory);
        });

        $this->app->extend(OpenApiCommand::class, function (): OpenApiCommand {
            return new OpenApiCommand(
                $this->app->make(OpenApiFactoryInterface::class),
                $this->app->make(NormalizerInterface::class)
            );
        });
    }
}
