<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Represents an OAuth/OIDC client application.
 */
class OAuthClient
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly string $clientSecret,
        public readonly array $redirectUris,
        public readonly array $allowedScopes,
        public readonly string $type = 'confidential', // confidential or public
        public readonly bool $active = true,
        public readonly ?DateTimeImmutable $createdAt = null,
    ) {
    }

    /**
     * Verify redirect URI is allowed.
     */
    public function isRedirectUriAllowed(string $redirectUri): bool
    {
        return in_array($redirectUri, $this->redirectUris, true);
    }

    /**
     * Verify scope is allowed.
     */
    public function isScopeAllowed(string $scope): bool
    {
        return in_array($scope, $this->allowedScopes, true);
    }

    /**
     * Verify client secret.
     */
    public function verifySecret(string $secret): bool
    {
        return hash_equals($this->clientSecret, $secret);
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            name: $data['name'],
            clientSecret: $data['client_secret'],
            redirectUris: is_string($data['redirect_uris']) ? json_decode($data['redirect_uris'], true) : $data['redirect_uris'],
            allowedScopes: is_string($data['allowed_scopes']) ? json_decode($data['allowed_scopes'], true) : $data['allowed_scopes'],
            type: $data['type'] ?? 'confidential',
            active: (bool) ($data['active'] ?? true),
            createdAt: isset($data['created_at']) ? new DateTimeImmutable($data['created_at']) : null,
        );
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'client_secret' => $this->clientSecret,
            'redirect_uris' => json_encode($this->redirectUris),
            'allowed_scopes' => json_encode($this->allowedScopes),
            'type' => $this->type,
            'active' => $this->active,
            'created_at' => $this->createdAt?->format('Y-m-d H:i:s'),
        ];
    }
}
