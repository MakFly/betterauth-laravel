<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

/**
 * Provider user entity for OAuth authentication.
 */
class ProviderUser
{
    public function __construct(
        public readonly string $providerId,
        public readonly string $email,
        public readonly ?string $name,
        public readonly ?string $avatar,
        public readonly bool $emailVerified,
        public readonly array $rawData,
    ) {
    }

    /**
     * Create a ProviderUser from an array of data.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            providerId: $data['provider_id'],
            email: $data['email'],
            name: $data['name'] ?? null,
            avatar: $data['avatar'] ?? null,
            emailVerified: $data['email_verified'] ?? false,
            rawData: $data['raw_data'] ?? [],
        );
    }

    /**
     * Convert the ProviderUser to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'provider_id' => $this->providerId,
            'email' => $this->email,
            'name' => $this->name,
            'avatar' => $this->avatar,
            'email_verified' => $this->emailVerified,
            'raw_data' => $this->rawData,
        ];
    }
}
