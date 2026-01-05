<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Authentication Mode
    |--------------------------------------------------------------------------
    |
    | BetterAuth supports the following authentication modes:
    |
    | - "api": Stateless token-based auth with Paseto V4
    |          Best for: SPAs (React, Vue), Mobile apps, APIs
    |          Guard: betterauth
    |
    | - "session": Traditional server-side session auth with enhanced tracking
    |              Best for: Traditional web apps (Blade, Livewire), SSR apps
    |              Guard: betterauth.session
    |              Features: Multi-device management, session tracking, device info
    |
    | ⚠️  "hybrid" mode is NOT AVAILABLE for Laravel (Symfony only)
    |
    */
    'mode' => env('BETTER_AUTH_MODE', 'api'),

    /*
    |--------------------------------------------------------------------------
    | Secret Key
    |--------------------------------------------------------------------------
    |
    | This secret is used for signing Paseto V4 tokens. It should be a
    | cryptographically secure random string of at least 32 characters.
    | Generate one with: php artisan betterauth:secret
    |
    */
    'secret' => env('BETTER_AUTH_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | Token Configuration
    |--------------------------------------------------------------------------
    |
    | Configure token lifetimes and behavior for Paseto V4 tokens.
    |
    */
    'tokens' => [
        'access' => [
            'lifetime' => (int) env('BETTER_AUTH_ACCESS_TOKEN_LIFETIME', 3600), // 1 hour
        ],
        'refresh' => [
            'lifetime' => (int) env('BETTER_AUTH_REFRESH_TOKEN_LIFETIME', 2592000), // 30 days
            'rotation' => env('BETTER_AUTH_REFRESH_TOKEN_ROTATION', true), // One-time use
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The Eloquent model used for users in your application.
    |
    */
    'user_model' => env('BETTER_AUTH_USER_MODEL', 'App\\Models\\User'),

    /*
    |--------------------------------------------------------------------------
    | ID Strategy
    |--------------------------------------------------------------------------
    |
    | The primary key strategy for entities:
    | - "uuid": UUID v7 (recommended, better for distributed systems)
    | - "ulid": ULID (sortable, URL-safe)
    | - "int": Auto-incrementing integers (legacy compatibility)
    |
    */
    'id_strategy' => env('BETTER_AUTH_ID_STRATEGY', 'uuid'),

    /*
    |--------------------------------------------------------------------------
    | Database Tables
    |--------------------------------------------------------------------------
    |
    | Customize the table names used by BetterAuth.
    |
    */
    'tables' => [
        'users' => 'users',
        'sessions' => 'better_auth_sessions',
        'refresh_tokens' => 'better_auth_refresh_tokens',
        'account_links' => 'better_auth_account_links',
        'email_verifications' => 'better_auth_email_verifications',
        'password_resets' => 'better_auth_password_resets',
        'magic_links' => 'better_auth_magic_links',
        'totp_secrets' => 'better_auth_totp_secrets',
        'device_info' => 'better_auth_device_info',
        'security_events' => 'better_auth_security_events',
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Hashing
    |--------------------------------------------------------------------------
    |
    | BetterAuth uses Argon2id by default. You can customize the options here.
    |
    */
    'password' => [
        'algorithm' => PASSWORD_ARGON2ID,
        'options' => [
            'memory_cost' => 65536, // 64 MB
            'time_cost' => 4,
            'threads' => 1,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Email Verification
    |--------------------------------------------------------------------------
    |
    | Configure email verification behavior.
    |
    */
    'verification' => [
        'enabled' => env('BETTER_AUTH_VERIFY_EMAIL', true),
        'token_lifetime' => 86400, // 24 hours
    ],

    /*
    |--------------------------------------------------------------------------
    | OAuth Providers
    |--------------------------------------------------------------------------
    |
    | Configure OAuth providers for social authentication.
    | Each provider requires client_id, client_secret, and redirect_uri.
    |
    */
    'oauth' => [
        'enabled' => env('BETTER_AUTH_OAUTH_ENABLED', false),
        'providers' => [
            'google' => [
                'enabled' => env('BETTER_AUTH_GOOGLE_ENABLED', false),
                'client_id' => env('BETTER_AUTH_GOOGLE_CLIENT_ID'),
                'client_secret' => env('BETTER_AUTH_GOOGLE_CLIENT_SECRET'),
                'redirect_uri' => env('BETTER_AUTH_GOOGLE_REDIRECT_URI'),
                'scopes' => ['openid', 'email', 'profile'],
            ],
            'github' => [
                'enabled' => env('BETTER_AUTH_GITHUB_ENABLED', false),
                'client_id' => env('BETTER_AUTH_GITHUB_CLIENT_ID'),
                'client_secret' => env('BETTER_AUTH_GITHUB_CLIENT_SECRET'),
                'redirect_uri' => env('BETTER_AUTH_GITHUB_REDIRECT_URI'),
                'scopes' => ['user:email'],
            ],
            'microsoft' => [
                'enabled' => env('BETTER_AUTH_MICROSOFT_ENABLED', false),
                'client_id' => env('BETTER_AUTH_MICROSOFT_CLIENT_ID'),
                'client_secret' => env('BETTER_AUTH_MICROSOFT_CLIENT_SECRET'),
                'redirect_uri' => env('BETTER_AUTH_MICROSOFT_REDIRECT_URI'),
                'scopes' => ['openid', 'email', 'profile'],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Two-Factor Authentication (2FA)
    |--------------------------------------------------------------------------
    |
    | Configure TOTP-based two-factor authentication.
    |
    */
    '2fa' => [
        'enabled' => env('BETTER_AUTH_2FA_ENABLED', false),
        'issuer' => env('BETTER_AUTH_2FA_ISSUER', config('app.name', 'BetterAuth')),
        'digits' => 6,
        'period' => 30,
        'algorithm' => 'sha1',
    ],

    /*
    |--------------------------------------------------------------------------
    | Magic Links
    |--------------------------------------------------------------------------
    |
    | Configure passwordless authentication via magic links.
    |
    */
    'magic_links' => [
        'enabled' => env('BETTER_AUTH_MAGIC_LINKS_ENABLED', false),
        'token_lifetime' => 900, // 15 minutes
    ],

    /*
    |--------------------------------------------------------------------------
    | Passkeys / WebAuthn
    |--------------------------------------------------------------------------
    |
    | Configure FIDO2/WebAuthn passkey authentication.
    |
    * @deprecated Passkeys are not yet implemented. Planned for future release.
    */
    'passkeys' => [
        'enabled' => false, // Not implemented yet
        'rp_name' => env('BETTER_AUTH_PASSKEYS_RP_NAME', config('app.name', 'BetterAuth')),
        'rp_id' => env('BETTER_AUTH_PASSKEYS_RP_ID'),
        'origin' => env('BETTER_AUTH_PASSKEYS_ORIGIN', config('app.url')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limiting for authentication endpoints.
    |
    */
    'rate_limiting' => [
        'enabled' => env('BETTER_AUTH_RATE_LIMITING', true),
        'max_attempts' => 5,
        'decay_minutes' => 15,
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Configure route registration and prefixes.
    |
    */
    'routes' => [
        'enabled' => true,
        'prefix' => 'auth',
        'middleware' => ['api'],
        'name_prefix' => 'betterauth.',
    ],

    /*
    |--------------------------------------------------------------------------
    | Optional User Fields
    |--------------------------------------------------------------------------
    |
    | Additional fields to include on the User model.
    |
    */
    'user_fields' => [
        'name' => true,
        'avatar' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Events
    |--------------------------------------------------------------------------
    |
    | Configure security event logging and monitoring.
    |
    */
    'security' => [
        'log_events' => env('BETTER_AUTH_LOG_SECURITY_EVENTS', true),
        'detect_suspicious' => env('BETTER_AUTH_DETECT_SUSPICIOUS', true),
        'device_tracking' => env('BETTER_AUTH_DEVICE_TRACKING', true),
    ],
];
