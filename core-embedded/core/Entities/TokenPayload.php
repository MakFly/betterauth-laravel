<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

/**
 * Token payload entity for JWT/Paseto tokens.
 */
class TokenPayload
{
    public function __construct(
        public readonly string $sub,
        public readonly int $iat,
        public readonly int $exp,
        public readonly string $type,
        public readonly ?array $data = null,
    ) {
    }

    /**
     * Create a TokenPayload from an array of data.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            sub: $data['sub'],
            iat: $data['iat'],
            exp: $data['exp'],
            type: $data['type'],
            data: $data['data'] ?? null,
        );
    }

    /**
     * Convert the TokenPayload to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $payload = [
            'sub' => $this->sub,
            'iat' => $this->iat,
            'exp' => $this->exp,
            'type' => $this->type,
        ];

        if ($this->data !== null) {
            $payload['data'] = $this->data;
        }

        return $payload;
    }

    /**
     * Check if the token is expired.
     */
    public function isExpired(): bool
    {
        return time() >= $this->exp;
    }

    /**
     * Check if the token is still valid.
     */
    public function isValid(): bool
    {
        return !$this->isExpired();
    }
}
