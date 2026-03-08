<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use BetterAuth\Contracts\AuthUserInterface;
use BetterAuth\Contracts\PasswordHolderInterface;
use DateTimeImmutable;
use Doctrine\ORM\Mapping as ORM;

/**
 * Base User entity for BetterAuth.
 *
 * This MappedSuperclass does NOT define the ID - the child class must define it.
 * This allows flexibility between UUID (string) and INT (integer) strategies.
 *
 * Implements BetterAuth contracts (AuthUserInterface, PasswordHolderInterface) for framework-agnostic integration.
 *
 * @example UUID strategy:
 * ```php
 * #[ORM\Entity]
 * class User extends BaseUser {
 *     #[ORM\Id]
 *     #[ORM\Column(type: 'string', length: 36)]
 *     protected string $id;
 * }
 * ```
 * @example INT strategy:
 * ```php
 * #[ORM\Entity]
 * class User extends BaseUser {
 *     #[ORM\Id]
 *     #[ORM\GeneratedValue]
 *     #[ORM\Column(type: 'integer')]
 *     protected ?int $id = null;
 * }
 * ```
 */
#[ORM\MappedSuperclass]
#[ORM\HasLifecycleCallbacks]
abstract class User implements AuthUserInterface, PasswordHolderInterface
{
    #[ORM\Column(type: 'string', length: 255, unique: true)]
    protected string $email;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    protected ?string $password = null;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    protected array $roles = ['ROLE_USER'];

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    protected ?string $username = null;

    #[ORM\Column(type: 'text', nullable: true)]
    protected ?string $avatar = null;

    #[ORM\Column(type: 'boolean')]
    protected bool $emailVerified = false;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    protected ?DateTimeImmutable $emailVerifiedAt = null;

    #[ORM\Column(type: 'datetime_immutable')]
    protected DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'datetime_immutable')]
    protected DateTimeImmutable $updatedAt;

    #[ORM\Column(type: 'json', nullable: true)]
    protected ?array $metadata = null;

    public function __construct()
    {
        $this->createdAt = new DateTimeImmutable();
        $this->updatedAt = new DateTimeImmutable();
    }

    /**
     * Get the user ID.
     * Must be implemented by child class based on ID strategy.
     */
    abstract public function getId(): string|int|null;

    /**
     * Set the user ID.
     * Must be implemented by child class based on ID strategy.
     */
    abstract public function setId(string|int $id): static;

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    /**
     * @see PasswordHolderInterface
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(?string $password): static
    {
        $this->password = $password;

        return $this;
    }

    /**
     * The public representation of the user (e.g. a username, an email address, etc.)
     *
     * @see AuthUserInterface
     */
    public function getUserIdentifier(): string
    {
        return $this->email;
    }

    /**
     * @see AuthUserInterface
     *
     * @return string[]
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // Guarantee every user at least has ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    /**
     * @param string[] $roles
     */
    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @see AuthUserInterface
     */
    public function eraseCredentials(): void
    {
        // If you store any temporary, sensitive data on the user, clear it here
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(?string $username): static
    {
        $this->username = $username;

        return $this;
    }

    public function getAvatar(): ?string
    {
        return $this->avatar;
    }

    public function setAvatar(?string $avatar): static
    {
        $this->avatar = $avatar;

        return $this;
    }

    public function isEmailVerified(): bool
    {
        return $this->emailVerified;
    }

    public function setEmailVerified(bool $emailVerified): static
    {
        $this->emailVerified = $emailVerified;

        return $this;
    }

    public function getEmailVerifiedAt(): ?DateTimeImmutable
    {
        return $this->emailVerifiedAt;
    }

    public function setEmailVerifiedAt(?DateTimeImmutable $emailVerifiedAt): static
    {
        $this->emailVerifiedAt = $emailVerifiedAt;

        return $this;
    }

    public function getCreatedAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    public function getUpdatedAt(): DateTimeImmutable
    {
        return $this->updatedAt;
    }

    public function setUpdatedAt(DateTimeImmutable $updatedAt): static
    {
        $this->updatedAt = $updatedAt;

        return $this;
    }

    public function getMetadata(): ?array
    {
        return $this->metadata;
    }

    public function setMetadata(?array $metadata): static
    {
        $this->metadata = $metadata;

        return $this;
    }

    /**
     * Check if user has a password (for Magic Link users who might not have one).
     */
    public function hasPassword(): bool
    {
        return $this->password !== null && $this->password !== '';
    }

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        if (!isset($this->createdAt)) {
            $this->createdAt = new DateTimeImmutable();
        }
        if (!isset($this->updatedAt)) {
            $this->updatedAt = new DateTimeImmutable();
        }
    }

    #[ORM\PreUpdate]
    public function onPreUpdate(): void
    {
        $this->updatedAt = new DateTimeImmutable();
    }

}
