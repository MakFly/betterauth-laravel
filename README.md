# BetterAuth for Laravel

**Modern authentication for Laravel with Paseto V4 tokens, 2FA, and Magic Links**

[![CI](https://github.com/MakFly/betterauth-laravel/actions/workflows/ci.yml/badge.svg)](https://github.com/MakFly/betterauth-laravel/actions/workflows/ci.yml)
[![PHP Version](https://img.shields.io/badge/php-8.2%2B-blue.svg)](https://php.net)
[![Laravel](https://img.shields.io/badge/laravel-10%20%7C%2011%20%7C%2012-red.svg)](https://laravel.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[Installation](#installation) • [Quick Start](#quick-start) • [Features](#features) • [API Reference](#api-reference)

---

## Why BetterAuth?

| JWT | BetterAuth (Paseto V4) |
|-----|------------------------|
| Signed only | **Encrypted + Authenticated** |
| Algorithm confusion attacks | Single secure algorithm |
| Complex key management | Simple symmetric keys |
| Base64 encoded payload | Encrypted payload |

BetterAuth uses **Paseto V4** (Platform-Agnostic Security Tokens) - a modern, secure alternative to JWT that eliminates entire classes of vulnerabilities by design.

---

## Installation

```bash
composer require betterauth/laravel
```

```bash
php artisan betterauth:install
```

That's it. The installer configures everything automatically.

---

## Quick Start

```php
use BetterAuth\Laravel\Facades\BetterAuth;

// Register
$result = BetterAuth::signUp([
    'email' => 'user@example.com',
    'password' => 'securepassword',
]);

// Login
$result = BetterAuth::signIn('user@example.com', 'password');
// → access_token, refresh_token, user

// Verify token
$payload = BetterAuth::verify($accessToken);

// Protected routes
Route::middleware('auth:betterauth')->get('/me', fn() => auth()->user());
```

---

## Features

### Core Authentication

- **Paseto V4 Tokens** - Encrypted, not just signed
- **Argon2id Passwords** - Memory-hard hashing (PHC winner)
- **Refresh Token Rotation** - One-time use with automatic rotation
- **UUID v7 IDs** - Time-ordered, database-friendly

### Advanced Features

- **Two-Factor Auth (TOTP)** - With recovery codes
- **Magic Links** - Passwordless email authentication
- **OAuth Providers** - Google, GitHub, Facebook, and more
- **Passkeys/WebAuthn** - Biometric authentication *(coming soon)*

### Laravel Native

- Works with `Auth::guard('betterauth')`
- Eloquent models and migrations
- Artisan commands
- Event dispatching

---

## Requirements

| Requirement | Version |
|-------------|---------|
| PHP | 8.2+ |
| Laravel | 10, 11, 12 |
| Database | PostgreSQL, MySQL, SQLite |

---

## Configuration

After installation, configure via environment variables:

```env
BETTERAUTH_SECRET=your-64-character-secret-key
BETTERAUTH_MODE=api
BETTERAUTH_ACCESS_LIFETIME=3600
BETTERAUTH_REFRESH_LIFETIME=2592000
```

Or edit `config/betterauth.php`:

```php
return [
    'mode' => 'api',                    // 'api', 'session', 'hybrid'
    'secret' => env('BETTERAUTH_SECRET'),
    'tokens' => [
        'access_lifetime' => 3600,      // 1 hour
        'refresh_lifetime' => 2592000,  // 30 days
    ],
    'user_model' => App\Models\User::class,
    'id_strategy' => 'uuid',            // 'uuid' or 'int'
];
```

Generate a new secret key:

```bash
php artisan betterauth:secret
```

---

## API Reference

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Create new account |
| `POST` | `/auth/login` | Authenticate user |
| `GET` | `/auth/me` | Get current user |
| `POST` | `/auth/refresh` | Refresh access token |
| `POST` | `/auth/logout` | Revoke refresh token |
| `POST` | `/auth/revoke-all` | Revoke all tokens |
| `PUT` | `/auth/password` | Update password |

### Two-Factor Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/2fa/status` | Check 2FA status |
| `POST` | `/auth/2fa/setup` | Get QR code |
| `POST` | `/auth/2fa/enable` | Enable 2FA |
| `POST` | `/auth/2fa/verify` | Verify TOTP code |
| `POST` | `/auth/2fa/recovery` | Use recovery code |
| `DELETE` | `/auth/2fa` | Disable 2FA |

### Magic Links

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/magic-link` | Send magic link |
| `GET` | `/auth/magic-link/verify` | Verify and login |

---

## User Model

Add the `HasBetterAuth` trait to your User model:

```php
use BetterAuth\Laravel\Models\Traits\HasBetterAuth;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasBetterAuth;

    protected $fillable = ['email', 'password', 'name'];
}
```

The trait provides:

```php
$user->getRoles();              // ['ROLE_USER', 'ROLE_ADMIN']
$user->hasRole('ROLE_ADMIN');   // true/false
$user->addRole('ROLE_ADMIN');
$user->removeRole('ROLE_ADMIN');
$user->createTokens();          // Generate new token pair
$user->revokeAllTokens();       // Revoke all refresh tokens
```

---

## Two-Factor Authentication

Enable in configuration:

```php
// config/betterauth.php
'two_factor' => [
    'enabled' => true,
    'issuer' => 'My App',
],
```

Using the service:

```php
use BetterAuth\Laravel\Services\TwoFactorService;

$twoFactor = app(TwoFactorService::class);

// Setup
$setup = $twoFactor->generateSecret($user);
// → secret, qr_code_url, uri

// Enable
$result = $twoFactor->verifyAndEnable($user, '123456');
// → enabled, recovery_codes

// Verify
$valid = $twoFactor->verify($user, '123456');
```

---

## Magic Links

Enable in configuration:

```php
// config/betterauth.php
'magic_link' => [
    'enabled' => true,
    'expire' => 15, // minutes
],
```

Using the service:

```php
use BetterAuth\Laravel\Services\MagicLinkService;

$magicLink = app(MagicLinkService::class);
$magicLink->send('user@example.com');
```

---

## Events

| Event | Trigger |
|-------|---------|
| `UserRegistered` | New user signs up |
| `UserLoggedIn` | Successful authentication |
| `UserLoggedOut` | User signs out |
| `TokenRefreshed` | Refresh token used |
| `PasswordChanged` | Password updated |
| `TwoFactorEnabled` | 2FA activated |
| `TwoFactorDisabled` | 2FA deactivated |
| `MagicLinkSent` | Magic link email sent |

```php
// EventServiceProvider.php
protected $listen = [
    \BetterAuth\Laravel\Events\UserRegistered::class => [
        \App\Listeners\SendWelcomeEmail::class,
    ],
];
```

---

## Middleware

```php
// Require authentication
Route::middleware('auth:betterauth')->group(function () {
    // Protected routes
});

// Require email verification
Route::middleware(['auth:betterauth', EnsureEmailIsVerified::class])->group(...);

// Require 2FA enabled
Route::middleware(['auth:betterauth', RequiresTwoFactor::class])->group(...);
```

---

## Security

### Token Security (Paseto V4)

- **XChaCha20-Poly1305** encryption
- Tokens are **encrypted**, not just signed
- No algorithm confusion attacks
- No key type confusion

### Password Security (Argon2id)

- Winner of Password Hashing Competition
- Memory-hard to prevent GPU attacks
- Configurable memory/time/threads

### Refresh Token Security

- **Hashed** before storage (SHA-256)
- **One-time use** - revoked after refresh
- **Automatic rotation** - new token on each refresh

---

## Testing

```bash
# Run tests
composer test

# With coverage
composer test-coverage

# Static analysis
composer phpstan
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

