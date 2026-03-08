<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Represents an OAuth authorization code (short-lived).
 */
class AuthorizationCode
{
    public function __construct(
        public readonly string $code,
        public readonly string $clientId,
        public readonly string $userId,
        public readonly string $redirectUri,
        public readonly array $scopes,
        public readonly DateTimeImmutable $expiresAt,
        public readonly ?string $codeChallenge = null,
        public readonly ?string $codeChallengeMethod = null,
        public readonly ?DateTimeImmutable $createdAt = null,
        public readonly bool $used = false,
    ) {
    }

    /**
     * Check if code is valid (not expired and not used).
     */
    public function isValid(): bool
    {
        return !$this->used && $this->expiresAt > new DateTimeImmutable();
    }

    /**
     * Verify PKCE challenge.
     */
    public function verifyChallenge(string $verifier): bool
    {
        if ($this->codeChallenge === null) {
            return true; // No PKCE required
        }

        if ($this->codeChallengeMethod === 'S256') {
            $hash = base64_encode(hash('sha256', $verifier, true));
            $hash = rtrim(strtr($hash, '+/', '-_'), '=');

            return hash_equals($this->codeChallenge, $hash);
        }

        // Plain method
        return hash_equals($this->codeChallenge, $verifier);
    }

    public static function fromArray(array $data): self
    {
        return new self(
            code: $data['code'],
            clientId: $data['client_id'],
            userId: $data['user_id'],
            redirectUri: $data['redirect_uri'],
            scopes: is_string($data['scopes']) ? json_decode($data['scopes'], true) : $data['scopes'],
            expiresAt: new DateTimeImmutable($data['expires_at']),
            codeChallenge: $data['code_challenge'] ?? null,
            codeChallengeMethod: $data['code_challenge_method'] ?? null,
            createdAt: isset($data['created_at']) ? new DateTimeImmutable($data['created_at']) : null,
            used: (bool) ($data['used'] ?? false),
        );
    }

    public function toArray(): array
    {
        return [
            'code' => $this->code,
            'client_id' => $this->clientId,
            'user_id' => $this->userId,
            'redirect_uri' => $this->redirectUri,
            'scopes' => json_encode($this->scopes),
            'expires_at' => $this->expiresAt->format('Y-m-d H:i:s'),
            'code_challenge' => $this->codeChallenge,
            'code_challenge_method' => $this->codeChallengeMethod,
            'created_at' => $this->createdAt?->format('Y-m-d H:i:s'),
            'used' => $this->used,
        ];
    }
}
