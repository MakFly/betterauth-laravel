<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Concrete RefreshToken implementation for PDO repositories.
 *
 * This class provides a simple, framework-agnostic RefreshToken entity
 * that can be used directly with PDO storage adapters.
 *
 * For Symfony applications, use the generated RefreshToken entity instead.
 */
class SimpleRefreshToken extends RefreshToken
{
    protected string $userId;

    public function getUserId(): string|int
    {
        return $this->userId;
    }

    public function setUserId(string|int $userId): static
    {
        $this->userId = (string) $userId;

        return $this;
    }

    /**
     * Create a SimpleRefreshToken from an array of data (typically from database).
     */
    public static function fromArray(array $data): self
    {
        $token = new self();

        if (isset($data['token'])) {
            $token->setToken($data['token']);
        }
        if (isset($data['user_id'])) {
            $token->setUserId($data['user_id']);
        }
        if (isset($data['expires_at'])) {
            $expiresAt = $data['expires_at'] instanceof DateTimeImmutable
                ? $data['expires_at']
                : new DateTimeImmutable($data['expires_at']);
            $token->setExpiresAt($expiresAt);
        }
        if (isset($data['created_at'])) {
            $createdAt = $data['created_at'] instanceof DateTimeImmutable
                ? $data['created_at']
                : new DateTimeImmutable($data['created_at']);
            $token->setCreatedAt($createdAt);
        }
        if (isset($data['revoked'])) {
            $token->setRevoked((bool) $data['revoked']);
        }
        if (isset($data['replaced_by'])) {
            $token->setReplacedBy($data['replaced_by']);
        }

        return $token;
    }

    /**
     * Convert to array for storage.
     */
    public function toArray(): array
    {
        return [
            'token' => $this->getToken(),
            'user_id' => $this->getUserId(),
            'expires_at' => $this->getExpiresAt()->format('Y-m-d H:i:s'),
            'created_at' => $this->getCreatedAt()->format('Y-m-d H:i:s'),
            'revoked' => $this->isRevoked(),
            'replaced_by' => $this->getReplacedBy(),
        ];
    }
}
