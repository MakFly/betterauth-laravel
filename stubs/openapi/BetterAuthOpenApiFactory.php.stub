<?php

declare(strict_types=1);

namespace App\OpenApi;

use ApiPlatform\OpenApi\Factory\OpenApiFactoryInterface;
use ApiPlatform\OpenApi\Model;
use ApiPlatform\OpenApi\OpenApi;

final class BetterAuthOpenApiFactory implements OpenApiFactoryInterface
{
    public function __construct(private readonly OpenApiFactoryInterface $decorated)
    {
    }

    public function __invoke(array $context = []): OpenApi
    {
        $openApi = ($this->decorated)($context);

        if (! config('betterauth_openapi.enabled', true)) {
            return $openApi;
        }

        $openApi = $this->ensureSecurityScheme($openApi);
        $tag = (string) config('betterauth_openapi.tag', 'BetterAuth');
        $prefix = trim((string) config('betterauth.routes.prefix', 'auth'), '/');
        $basePath = '/'.$prefix;

        $this->addCorePaths($openApi, $basePath, $tag);

        if ((bool) config('betterauth.oauth.enabled', false)) {
            $this->addOAuthPaths($openApi, $basePath, $tag);
        }

        if ((bool) config('betterauth.magic_links.enabled', false)) {
            $this->addMagicLinkPaths($openApi, $basePath, $tag);
        }

        if ((bool) config('betterauth.2fa.enabled', false)) {
            $this->addTwoFactorPaths($openApi, $basePath, $tag);
        }

        return $openApi;
    }

    private function ensureSecurityScheme(OpenApi $openApi): OpenApi
    {
        $components = $openApi->getComponents();
        $schemeName = (string) config('betterauth_openapi.security_scheme', 'betterAuthBearer');
        $securitySchemes = $components->getSecuritySchemes() ?? new \ArrayObject();

        if (! isset($securitySchemes[$schemeName])) {
            $securitySchemes[$schemeName] = new Model\SecurityScheme(
                type: 'http',
                description: 'BetterAuth access token',
                name: 'Authorization',
                in: 'header',
                scheme: 'bearer',
                bearerFormat: 'Paseto'
            );
        }

        return $openApi->withComponents($components->withSecuritySchemes($securitySchemes));
    }

    private function addCorePaths(OpenApi $openApi, string $basePath, string $tag): void
    {
        $this->addPath(
            $openApi,
            $basePath.'/register',
            post: $this->operation(
                operationId: 'betterAuthRegister',
                tag: $tag,
                summary: 'Register a new user',
                requestSchema: [
                    'type' => 'object',
                    'required' => ['email', 'password'],
                    'properties' => [
                        'email' => ['type' => 'string', 'format' => 'email'],
                        'password' => ['type' => 'string', 'minLength' => 8],
                        'name' => ['type' => 'string'],
                    ],
                ],
                responseSchema: [
                    'type' => 'object',
                    'properties' => [
                        'data' => [
                            'type' => 'object',
                            'properties' => [
                                'user' => ['type' => 'object'],
                                'access_token' => ['type' => 'string'],
                                'refresh_token' => ['type' => 'string'],
                                'token_type' => ['type' => 'string', 'example' => 'Bearer'],
                                'expires_in' => ['type' => 'integer'],
                            ],
                        ],
                    ],
                ],
                secured: false,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/login',
            post: $this->operation(
                operationId: 'betterAuthLogin',
                tag: $tag,
                summary: 'Authenticate user',
                requestSchema: [
                    'type' => 'object',
                    'required' => ['email', 'password'],
                    'properties' => [
                        'email' => ['type' => 'string', 'format' => 'email'],
                        'password' => ['type' => 'string'],
                    ],
                ],
                responseSchema: [
                    'type' => 'object',
                    'properties' => [
                        'data' => [
                            'type' => 'object',
                            'properties' => [
                                'user' => ['type' => 'object'],
                                'access_token' => ['type' => 'string'],
                                'refresh_token' => ['type' => 'string'],
                                'token_type' => ['type' => 'string', 'example' => 'Bearer'],
                                'expires_in' => ['type' => 'integer'],
                            ],
                        ],
                    ],
                ],
                secured: false,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/refresh',
            post: $this->operation(
                operationId: 'betterAuthRefresh',
                tag: $tag,
                summary: 'Refresh access token',
                requestSchema: [
                    'type' => 'object',
                    'required' => ['refresh_token'],
                    'properties' => [
                        'refresh_token' => ['type' => 'string'],
                    ],
                ],
                responseSchema: [
                    'type' => 'object',
                    'properties' => [
                        'data' => [
                            'type' => 'object',
                            'properties' => [
                                'access_token' => ['type' => 'string'],
                                'refresh_token' => ['type' => 'string'],
                                'token_type' => ['type' => 'string', 'example' => 'Bearer'],
                                'expires_in' => ['type' => 'integer'],
                            ],
                        ],
                    ],
                ],
                secured: false,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/me',
            get: $this->operation(
                operationId: 'betterAuthMe',
                tag: $tag,
                summary: 'Get current authenticated user',
                responseSchema: [
                    'type' => 'object',
                    'properties' => [
                        'data' => ['type' => 'object'],
                    ],
                ],
                secured: true,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/logout',
            post: $this->operation(
                operationId: 'betterAuthLogout',
                tag: $tag,
                summary: 'Logout current user',
                responseSchema: [
                    'type' => 'object',
                    'properties' => [
                        'message' => ['type' => 'string'],
                    ],
                ],
                secured: true,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/revoke-all',
            post: $this->operation(
                operationId: 'betterAuthRevokeAll',
                tag: $tag,
                summary: 'Revoke all active tokens',
                responseSchema: [
                    'type' => 'object',
                    'properties' => [
                        'message' => ['type' => 'string'],
                    ],
                ],
                secured: true,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/password',
            put: $this->operation(
                operationId: 'betterAuthUpdatePassword',
                tag: $tag,
                summary: 'Update account password',
                requestSchema: [
                    'type' => 'object',
                    'required' => ['current_password', 'new_password'],
                    'properties' => [
                        'current_password' => ['type' => 'string'],
                        'new_password' => ['type' => 'string', 'minLength' => 8],
                    ],
                ],
                responseSchema: [
                    'type' => 'object',
                    'properties' => [
                        'message' => ['type' => 'string'],
                    ],
                ],
                secured: true,
            )
        );
    }

    private function addOAuthPaths(OpenApi $openApi, string $basePath, string $tag): void
    {
        $providerParameter = new Model\Parameter('provider', 'path', 'OAuth provider name', true, false, null, ['type' => 'string']);

        $this->addPath(
            $openApi,
            $basePath.'/oauth/{provider}',
            get: $this->operation(
                operationId: 'betterAuthOAuthRedirect',
                tag: $tag,
                summary: 'Redirect to OAuth provider',
                responseSchema: ['type' => 'object'],
                secured: false,
                parameters: [$providerParameter],
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/oauth/{provider}/callback',
            get: $this->operation(
                operationId: 'betterAuthOAuthCallback',
                tag: $tag,
                summary: 'OAuth callback endpoint',
                responseSchema: ['type' => 'object'],
                secured: false,
                parameters: [$providerParameter],
            )
        );
    }

    private function addMagicLinkPaths(OpenApi $openApi, string $basePath, string $tag): void
    {
        $this->addPath(
            $openApi,
            $basePath.'/magic-link',
            post: $this->operation(
                operationId: 'betterAuthMagicLinkSend',
                tag: $tag,
                summary: 'Send a magic link',
                requestSchema: [
                    'type' => 'object',
                    'required' => ['email'],
                    'properties' => [
                        'email' => ['type' => 'string', 'format' => 'email'],
                    ],
                ],
                responseSchema: ['type' => 'object'],
                secured: false,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/magic-link/verify',
            get: $this->operation(
                operationId: 'betterAuthMagicLinkVerify',
                tag: $tag,
                summary: 'Verify magic link token',
                responseSchema: ['type' => 'object'],
                secured: false,
            )
        );

        $this->addPath(
            $openApi,
            $basePath.'/magic-link/check',
            post: $this->operation(
                operationId: 'betterAuthMagicLinkCheck',
                tag: $tag,
                summary: 'Check magic link status',
                requestSchema: [
                    'type' => 'object',
                    'required' => ['token'],
                    'properties' => [
                        'token' => ['type' => 'string'],
                    ],
                ],
                responseSchema: ['type' => 'object'],
                secured: false,
            )
        );
    }

    private function addTwoFactorPaths(OpenApi $openApi, string $basePath, string $tag): void
    {
        $this->addPath($openApi, $basePath.'/2fa/status', get: $this->operation(
            operationId: 'betterAuthTwoFactorStatus',
            tag: $tag,
            summary: 'Get 2FA status',
            responseSchema: ['type' => 'object'],
            secured: true,
        ));

        $this->addPath($openApi, $basePath.'/2fa/setup', post: $this->operation(
            operationId: 'betterAuthTwoFactorSetup',
            tag: $tag,
            summary: 'Setup 2FA',
            responseSchema: ['type' => 'object'],
            secured: true,
        ));

        $this->addPath($openApi, $basePath.'/2fa/enable', post: $this->operation(
            operationId: 'betterAuthTwoFactorEnable',
            tag: $tag,
            summary: 'Enable 2FA',
            requestSchema: [
                'type' => 'object',
                'required' => ['code'],
                'properties' => [
                    'code' => ['type' => 'string'],
                ],
            ],
            responseSchema: ['type' => 'object'],
            secured: true,
        ));

        $this->addPath($openApi, $basePath.'/2fa/verify', post: $this->operation(
            operationId: 'betterAuthTwoFactorVerify',
            tag: $tag,
            summary: 'Verify 2FA code',
            requestSchema: [
                'type' => 'object',
                'required' => ['code'],
                'properties' => [
                    'code' => ['type' => 'string'],
                ],
            ],
            responseSchema: ['type' => 'object'],
            secured: true,
        ));

        $this->addPath($openApi, $basePath.'/2fa/recovery', post: $this->operation(
            operationId: 'betterAuthTwoFactorRecovery',
            tag: $tag,
            summary: 'Verify recovery code',
            requestSchema: [
                'type' => 'object',
                'required' => ['code'],
                'properties' => [
                    'code' => ['type' => 'string'],
                ],
            ],
            responseSchema: ['type' => 'object'],
            secured: true,
        ));

        $this->addPath($openApi, $basePath.'/2fa/recovery-codes', post: $this->operation(
            operationId: 'betterAuthTwoFactorRegenerateRecoveryCodes',
            tag: $tag,
            summary: 'Regenerate recovery codes',
            responseSchema: ['type' => 'object'],
            secured: true,
        ));

        $this->addPath($openApi, $basePath.'/2fa', delete: $this->operation(
            operationId: 'betterAuthTwoFactorDisable',
            tag: $tag,
            summary: 'Disable 2FA',
            requestSchema: [
                'type' => 'object',
                'required' => ['password'],
                'properties' => [
                    'password' => ['type' => 'string'],
                ],
            ],
            responseSchema: ['type' => 'object'],
            secured: true,
        ));
    }

    private function operation(
        string $operationId,
        string $tag,
        string $summary,
        array $responseSchema,
        bool $secured,
        ?array $requestSchema = null,
        ?array $parameters = null,
    ): Model\Operation {
        $responses = [
            '200' => new Model\Response('Successful response', new \ArrayObject([
                'application/json' => [
                    'schema' => $responseSchema,
                ],
            ])),
            '401' => new Model\Response('Unauthorized'),
            '422' => new Model\Response('Validation failed'),
        ];

        $requestBody = null;
        if (is_array($requestSchema)) {
            $requestBody = new Model\RequestBody(
                description: 'JSON payload',
                content: new \ArrayObject([
                    'application/json' => [
                        'schema' => $requestSchema,
                    ],
                ]),
                required: true,
            );
        }

        $security = $secured
            ? [[(string) config('betterauth_openapi.security_scheme', 'betterAuthBearer') => []]]
            : [];

        return new Model\Operation(
            operationId: $operationId,
            tags: [$tag],
            responses: $responses,
            summary: $summary,
            parameters: $parameters,
            requestBody: $requestBody,
            security: $security,
        );
    }

    private function addPath(
        OpenApi $openApi,
        string $path,
        ?Model\Operation $get = null,
        ?Model\Operation $post = null,
        ?Model\Operation $put = null,
        ?Model\Operation $delete = null,
    ): void {
        $openApi->getPaths()->addPath($path, new Model\PathItem(
            get: $get,
            post: $post,
            put: $put,
            delete: $delete,
        ));
    }
}
