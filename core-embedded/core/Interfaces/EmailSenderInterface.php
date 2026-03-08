<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

/**
 * Interface for sending authentication-related emails.
 */
interface EmailSenderInterface
{
    /**
     * Send a magic link email.
     *
     * @param string $to Recipient email address
     * @param string $magicLink The magic link URL
     *
     * @return bool True if sent successfully, false otherwise
     */
    public function sendMagicLink(string $to, string $magicLink): bool;

    /**
     * Send an email verification link.
     *
     * @param string $to Recipient email address
     * @param string $verificationLink The verification link URL
     *
     * @return bool True if sent successfully, false otherwise
     */
    public function sendVerificationEmail(string $to, string $verificationLink): bool;

    /**
     * Send a password reset email.
     *
     * @param string $to Recipient email address
     * @param string $resetLink The password reset link URL
     *
     * @return bool True if sent successfully, false otherwise
     */
    public function sendPasswordReset(string $to, string $resetLink): bool;

    /**
     * Send a two-factor authentication code.
     *
     * @param string $to Recipient email address
     * @param string $code The 2FA code
     *
     * @return bool True if sent successfully, false otherwise
     */
    public function sendTwoFactorCode(string $to, string $code): bool;
}
