<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

/**
 * Magic Link Email.
 *
 * Sent when a user requests passwordless authentication.
 */
final class MagicLinkMail extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public readonly string $url,
        public readonly int $expirationMinutes = 15,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'Your Magic Link',
        );
    }

    public function content(): Content
    {
        return new Content(
            html: 'betterauth::emails.magic-link',
            with: [
                'url' => $this->url,
                'expirationMinutes' => $this->expirationMinutes,
                'appName' => config('app.name', 'BetterAuth'),
            ],
        );
    }

    /**
     * Build the message (fallback for older Laravel versions).
     */
    public function build(): static
    {
        $appName = config('app.name', 'BetterAuth');

        return $this
            ->subject("Your Magic Link - {$appName}")
            ->html($this->renderHtmlContent());
    }

    /**
     * Render inline HTML content when view is not available.
     */
    private function renderHtmlContent(): string
    {
        $appName = config('app.name', 'BetterAuth');

        return <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Your Magic Link</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background: #f5f5f5; }
        .container { max-width: 600px; margin: 40px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #fff; padding: 24px; text-align: center; }
        .content { padding: 32px; }
        .button { display: inline-block; background: #6366f1; color: #fff !important; text-decoration: none; padding: 14px 32px; border-radius: 6px; font-weight: 600; margin: 24px 0; }
        .button:hover { background: #5558e8; }
        .footer { padding: 24px; text-align: center; color: #666; font-size: 14px; border-top: 1px solid #eee; }
        .warning { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 6px; padding: 12px; margin-top: 24px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0; font-size: 24px;">{$appName}</h1>
        </div>
        <div class="content">
            <h2 style="margin-top: 0;">Sign in with Magic Link</h2>
            <p>Click the button below to sign in to your account. This link will expire in {$this->expirationMinutes} minutes.</p>
            <p style="text-align: center;">
                <a href="{$this->url}" class="button">Sign In</a>
            </p>
            <div class="warning">
                <strong>Security Notice:</strong> If you didn't request this link, you can safely ignore this email. Someone may have entered your email by mistake.
            </div>
        </div>
        <div class="footer">
            <p>This email was sent by {$appName}</p>
            <p style="font-size: 12px; color: #999;">If the button doesn't work, copy and paste this URL: {$this->url}</p>
        </div>
    </div>
</body>
</html>
HTML;
    }
}
