<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Services;

use BetterAuth\Laravel\Events\MagicLinkSent;
use BetterAuth\Laravel\Events\MagicLinkVerified;
use BetterAuth\Laravel\Mail\MagicLinkMail;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

/**
 * Magic Link (Passwordless) Authentication Service.
 *
 * Enables passwordless authentication via email magic links.
 */
final class MagicLinkService
{
    public function __construct(
        private readonly string $table = 'better_auth_magic_links',
        private readonly int $expirationMinutes = 15,
    ) {}

    /**
     * Send a magic link to the given email address.
     */
    public function send(string $email): bool
    {
        // Revoke any existing unused tokens for this email
        $this->revokeExistingTokens($email);

        // Generate new token
        $token = $this->generateToken();
        $id = (string) Str::uuid7();

        // Store token
        DB::table($this->table)->insert([
            'id' => $id,
            'email' => $email,
            'token' => hash('sha256', $token),
            'expires_at' => now()->addMinutes($this->expirationMinutes),
            'used_at' => null,
            'created_at' => now(),
        ]);

        // Build magic link URL
        $url = $this->buildMagicLinkUrl($token, $email);

        // Send email
        Mail::to($email)->send(new MagicLinkMail($url, $this->expirationMinutes));

        Event::dispatch(new MagicLinkSent($email));

        return true;
    }

    /**
     * Verify a magic link token.
     *
     * @return array{email: string, user_id: string|null}|null
     */
    public function verify(string $token, string $email): ?array
    {
        $hashedToken = hash('sha256', $token);

        $record = DB::table($this->table)
            ->where('email', $email)
            ->where('token', $hashedToken)
            ->where('expires_at', '>', now())
            ->whereNull('used_at')
            ->first();

        if ($record === null) {
            return null;
        }

        // Mark as used (single-use)
        DB::table($this->table)
            ->where('id', $record->id)
            ->update(['used_at' => now()]);

        Event::dispatch(new MagicLinkVerified($email));

        return [
            'email' => $record->email,
            'user_id' => null, // Will be resolved by the controller
        ];
    }

    /**
     * Get email from magic link token without consuming it.
     */
    public function getEmailFromToken(string $token): ?string
    {
        $hashedToken = hash('sha256', $token);

        $record = DB::table($this->table)
            ->where('token', $hashedToken)
            ->where('expires_at', '>', now())
            ->whereNull('used_at')
            ->first();

        return $record?->email;
    }

    /**
     * Check if a magic link token is valid without consuming it.
     */
    public function isValid(string $token, string $email): bool
    {
        $hashedToken = hash('sha256', $token);

        return DB::table($this->table)
            ->where('email', $email)
            ->where('token', $hashedToken)
            ->where('expires_at', '>', now())
            ->whereNull('used_at')
            ->exists();
    }

    /**
     * Revoke all magic links for an email.
     */
    public function revokeForEmail(string $email): int
    {
        return DB::table($this->table)
            ->where('email', $email)
            ->whereNull('used_at')
            ->delete();
    }

    /**
     * Clean up expired tokens.
     */
    public function deleteExpired(): int
    {
        return DB::table($this->table)
            ->where('expires_at', '<', now())
            ->delete();
    }

    /**
     * Generate a secure random token.
     */
    private function generateToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * Revoke existing unused tokens for an email.
     */
    private function revokeExistingTokens(string $email): void
    {
        DB::table($this->table)
            ->where('email', $email)
            ->whereNull('used_at')
            ->delete();
    }

    /**
     * Build the magic link URL.
     */
    private function buildMagicLinkUrl(string $token, string $email): string
    {
        $prefix = config('betterauth.routes.prefix', 'auth');

        return url("{$prefix}/magic-link/verify").'?'.http_build_query([
            'token' => $token,
            'email' => $email,
        ]);
    }
}
