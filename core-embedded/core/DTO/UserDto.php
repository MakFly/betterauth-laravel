<?php

declare(strict_types=1);

namespace BetterAuth\Core\DTO;

use BetterAuth\Core\DTO\Attribute\ExcludeField;
use BetterAuth\Core\Entities\User;
use DateTimeImmutable;

/**
 * User Data Transfer Object for API responses.
 *
 * This DTO provides controlled serialization of User entities,
 * automatically excluding sensitive fields like password.
 *
 * Extend this class in your application to add custom fields:
 * ```php
 * class AppUserDto extends UserDto
 * {
 *     public ?string $customField = null;
 *
 *     public static function fromUser(User $user): static
 *     {
 *         $dto = parent::fromUser($user);
 *         $dto->customField = $user->getCustomField();
 *         return $dto;
 *     }
 * }
 * ```
 */
class UserDto
{
    public string|int|null $id = null;

    public string $email;

    #[ExcludeField]
    public ?string $password = null;

    /** @var string[] */
    public array $roles = ['ROLE_USER'];

    public ?string $username = null;

    public ?string $avatar = null;

    public bool $emailVerified = false;

    public ?DateTimeImmutable $emailVerifiedAt = null;

    public DateTimeImmutable $createdAt;

    public DateTimeImmutable $updatedAt;

    /** @var array<string, mixed>|null */
    public ?array $metadata = null;

    /**
     * Create a UserDto from a User entity.
     */
    public static function fromUser(User $user): self
    {
        $dto = new self();
        $dto->id = $user->getId();
        $dto->email = $user->getEmail();
        $dto->roles = $user->getRoles();
        $dto->username = $user->getUsername();
        $dto->avatar = $user->getAvatar();
        $dto->emailVerified = $user->isEmailVerified();
        $dto->emailVerifiedAt = $user->getEmailVerifiedAt();
        $dto->createdAt = $user->getCreatedAt();
        $dto->updatedAt = $user->getUpdatedAt();
        $dto->metadata = $user->getMetadata();

        return $dto;
    }

    /**
     * Convert to array for API responses.
     *
     * @param string[] $includeFields Additional fields to include (even if excluded by default)
     * @param string[] $excludeFields Additional fields to exclude
     */
    public function toArray(array $includeFields = [], array $excludeFields = []): array
    {
        $reflection = new \ReflectionClass($this);
        $result = [];

        foreach ($reflection->getProperties(\ReflectionProperty::IS_PUBLIC) as $property) {
            $name = $property->getName();

            // Check if explicitly excluded
            if (in_array($name, $excludeFields, true)) {
                continue;
            }

            // Check for ExcludeField attribute
            $attributes = $property->getAttributes(ExcludeField::class);
            if (!empty($attributes)) {
                /** @var ExcludeField $excludeAttr */
                $excludeAttr = $attributes[0]->newInstance();

                // Skip if excluded by default and not explicitly included
                if ($excludeAttr->defaultExcluded && !in_array($name, $includeFields, true)) {
                    continue;
                }
            }

            $value = $property->getValue($this);

            // Format DateTimeImmutable
            if ($value instanceof DateTimeImmutable) {
                $value = $value->format(\DateTimeInterface::ATOM);
            }

            $result[$name] = $value;
        }

        return $result;
    }

    /**
     * Convert to JSON-serializable array (excludes sensitive fields).
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
