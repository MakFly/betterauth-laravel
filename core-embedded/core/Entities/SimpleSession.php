<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Concrete Session implementation for PDO repositories.
 *
 * This class provides a simple, framework-agnostic Session entity
 * that can be used directly with PDO storage adapters.
 *
 * For Symfony applications, use the generated Session entity instead.
 */
class SimpleSession extends Session
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
     * Create a SimpleSession from an array of data (typically from database).
     */
    public static function fromArray(array $data): self
    {
        $session = new self();

        if (isset($data['token'])) {
            $session->setToken($data['token']);
        }
        if (isset($data['user_id'])) {
            $session->setUserId($data['user_id']);
        }
        if (isset($data['expires_at'])) {
            $expiresAt = $data['expires_at'] instanceof DateTimeImmutable
                ? $data['expires_at']
                : new DateTimeImmutable($data['expires_at']);
            $session->setExpiresAt($expiresAt);
        }
        if (isset($data['ip_address'])) {
            $session->setIpAddress($data['ip_address']);
        }
        if (isset($data['user_agent'])) {
            $session->setUserAgent($data['user_agent']);
        }
        if (isset($data['created_at'])) {
            $createdAt = $data['created_at'] instanceof DateTimeImmutable
                ? $data['created_at']
                : new DateTimeImmutable($data['created_at']);
            $session->setCreatedAt($createdAt);
        }
        if (isset($data['updated_at'])) {
            $updatedAt = $data['updated_at'] instanceof DateTimeImmutable
                ? $data['updated_at']
                : new DateTimeImmutable($data['updated_at']);
            $session->setUpdatedAt($updatedAt);
        }
        if (isset($data['metadata'])) {
            $metadata = is_string($data['metadata']) ? json_decode($data['metadata'], true) : $data['metadata'];
            $session->setMetadata($metadata);
        }

        return $session;
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
            'ip_address' => $this->getIpAddress(),
            'user_agent' => $this->getUserAgent(),
            'created_at' => $this->getCreatedAt()->format('Y-m-d H:i:s'),
            'updated_at' => $this->getUpdatedAt()->format('Y-m-d H:i:s'),
            'metadata' => $this->getMetadata(),
        ];
    }
}
