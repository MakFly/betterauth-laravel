<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Concrete User implementation for PDO repositories.
 *
 * This class provides a simple, framework-agnostic User entity
 * that can be used directly with PDO storage adapters.
 *
 * For Symfony applications, use the generated User entity instead.
 */
class SimpleUser extends User
{
    protected string $id;

    public function getId(): string|int|null
    {
        return $this->id ?? null;
    }

    public function setId(string|int $id): static
    {
        $this->id = (string) $id;

        return $this;
    }

    /**
     * Create a SimpleUser from an array of data (typically from database).
     */
    public static function fromArray(array $data): self
    {
        $user = new self();

        if (isset($data['id'])) {
            $user->setId($data['id']);
        }
        if (isset($data['email'])) {
            $user->setEmail($data['email']);
        }
        if (isset($data['password']) || isset($data['password_hash'])) {
            $user->setPassword($data['password'] ?? $data['password_hash']);
        }
        if (isset($data['username'])) {
            $user->setUsername($data['username']);
        }
        if (isset($data['avatar'])) {
            $user->setAvatar($data['avatar']);
        }
        if (isset($data['roles'])) {
            $roles = is_string($data['roles']) ? json_decode($data['roles'], true) : $data['roles'];
            $user->setRoles($roles ?? ['ROLE_USER']);
        }
        if (isset($data['email_verified'])) {
            $user->setEmailVerified((bool) $data['email_verified']);
        }
        if (isset($data['email_verified_at']) && $data['email_verified_at']) {
            $emailVerifiedAt = $data['email_verified_at'] instanceof DateTimeImmutable
                ? $data['email_verified_at']
                : new DateTimeImmutable($data['email_verified_at']);
            $user->setEmailVerifiedAt($emailVerifiedAt);
        }
        if (isset($data['created_at'])) {
            $createdAt = $data['created_at'] instanceof DateTimeImmutable
                ? $data['created_at']
                : new DateTimeImmutable($data['created_at']);
            $user->setCreatedAt($createdAt);
        }
        if (isset($data['updated_at'])) {
            $updatedAt = $data['updated_at'] instanceof DateTimeImmutable
                ? $data['updated_at']
                : new DateTimeImmutable($data['updated_at']);
            $user->setUpdatedAt($updatedAt);
        }
        if (isset($data['metadata'])) {
            $metadata = is_string($data['metadata']) ? json_decode($data['metadata'], true) : $data['metadata'];
            $user->setMetadata($metadata);
        }

        return $user;
    }

    /**
     * Convert to array for database storage.
     *
     * WARNING: This includes password_hash and should NEVER be sent in API responses.
     * Use toApiArray() or UserDto for API responses.
     */
    public function toArray(): array
    {
        return [
            'id' => $this->getId(),
            'email' => $this->getEmail(),
            'password_hash' => $this->getPassword(),
            'username' => $this->getUsername(),
            'avatar' => $this->getAvatar(),
            'roles' => $this->roles,
            'email_verified' => $this->isEmailVerified(),
            'email_verified_at' => $this->getEmailVerifiedAt()?->format('Y-m-d H:i:s'),
            'created_at' => $this->getCreatedAt()->format('Y-m-d H:i:s'),
            'updated_at' => $this->getUpdatedAt()->format('Y-m-d H:i:s'),
            'metadata' => $this->getMetadata(),
        ];
    }

    /**
     * Convert to array safe for API responses (excludes sensitive data).
     *
     * @param string[] $includeFields Additional fields to include
     * @param string[] $excludeFields Additional fields to exclude
     */
    public function toApiArray(array $includeFields = [], array $excludeFields = []): array
    {
        $data = [
            'id' => $this->getId(),
            'email' => $this->getEmail(),
            'username' => $this->getUsername(),
            'avatar' => $this->getAvatar(),
            'roles' => $this->getRoles(),
            'emailVerified' => $this->isEmailVerified(),
            'emailVerifiedAt' => $this->getEmailVerifiedAt()?->format(\DateTimeInterface::ATOM),
            'createdAt' => $this->getCreatedAt()->format(\DateTimeInterface::ATOM),
            'updatedAt' => $this->getUpdatedAt()->format(\DateTimeInterface::ATOM),
        ];

        // Add metadata if not excluded
        if (!in_array('metadata', $excludeFields, true)) {
            $data['metadata'] = $this->getMetadata();
        }

        // Add optional fields if explicitly requested
        foreach ($includeFields as $field) {
            if ($field === 'password' && !in_array('password', $excludeFields, true)) {
                $data['password'] = $this->getPassword();
            }
        }

        // Remove excluded fields
        foreach ($excludeFields as $field) {
            unset($data[$field]);
        }

        return $data;
    }
}
