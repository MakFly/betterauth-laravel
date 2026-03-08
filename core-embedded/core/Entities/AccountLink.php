<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Account Link entity.
 *
 * Represents a link between a user account and an OAuth provider.
 * Allows users to have multiple OAuth providers linked to a single account.
 *
 * Example: A user can login with Google OR GitHub, both linked to the same account.
 */
class AccountLink
{
    public function __construct(
        public readonly string $id,
        public readonly string $userId,
        public readonly string $provider,        // 'google', 'github', 'facebook', etc.
        public readonly string $providerId,      // ID from the OAuth provider
        public readonly ?string $providerEmail,  // Email from the OAuth provider
        public readonly bool $isPrimary,         // Is this the primary account link?
        public readonly string $status,          // 'pending', 'verified', 'revoked'
        public readonly DateTimeImmutable $linkedAt,
        public readonly ?array $metadata = null,  // Avatar, name, tokens, etc.
    ) {
    }

    /**
     * Create from array.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            userId: $data['user_id'] ?? $data['userId'],
            provider: $data['provider'],
            providerId: $data['provider_id'] ?? $data['providerId'],
            providerEmail: $data['provider_email'] ?? $data['providerEmail'] ?? null,
            isPrimary: $data['is_primary'] ?? $data['isPrimary'] ?? false,
            status: $data['status'] ?? 'verified',
            linkedAt: isset($data['linked_at'])
                ? new DateTimeImmutable($data['linked_at'])
                : (isset($data['linkedAt']) && $data['linkedAt'] instanceof DateTimeImmutable
                    ? $data['linkedAt']
                    : new DateTimeImmutable()),
            metadata: $data['metadata'] ?? null,
        );
    }

    /**
     * Convert to array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->userId,
            'provider' => $this->provider,
            'provider_id' => $this->providerId,
            'provider_email' => $this->providerEmail,
            'is_primary' => $this->isPrimary,
            'status' => $this->status,
            'linked_at' => $this->linkedAt->format('Y-m-d H:i:s'),
            'metadata' => $this->metadata,
        ];
    }

    /**
     * Check if the account link is verified.
     */
    public function isVerified(): bool
    {
        return $this->status === 'verified';
    }

    /**
     * Check if the account link is pending.
     */
    public function isPending(): bool
    {
        return $this->status === 'pending';
    }

    /**
     * Check if the account link is revoked.
     */
    public function isRevoked(): bool
    {
        return $this->status === 'revoked';
    }

    /**
     * Create a copy with updated primary status.
     */
    public function withPrimaryStatus(bool $isPrimary): self
    {
        return new self(
            id: $this->id,
            userId: $this->userId,
            provider: $this->provider,
            providerId: $this->providerId,
            providerEmail: $this->providerEmail,
            isPrimary: $isPrimary,
            status: $this->status,
            linkedAt: $this->linkedAt,
            metadata: $this->metadata,
        );
    }

    /**
     * Create a copy with updated status.
     */
    public function withStatus(string $status): self
    {
        return new self(
            id: $this->id,
            userId: $this->userId,
            provider: $this->provider,
            providerId: $this->providerId,
            providerEmail: $this->providerEmail,
            isPrimary: $this->isPrimary,
            status: $status,
            linkedAt: $this->linkedAt,
            metadata: $this->metadata,
        );
    }
}
