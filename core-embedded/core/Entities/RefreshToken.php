<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;
use Doctrine\ORM\Mapping as ORM;

/**
 * Base RefreshToken entity for BetterAuth.
 *
 * This MappedSuperclass does NOT define the userId type - the child class must define it.
 * This allows flexibility between UUID (string) and INT (integer) user ID strategies.
 */
#[ORM\MappedSuperclass]
#[ORM\HasLifecycleCallbacks]
abstract class RefreshToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'string', length: 255)]
    protected string $token;

    #[ORM\Column(type: 'datetime_immutable')]
    protected DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'datetime_immutable')]
    protected DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'boolean')]
    protected bool $revoked = false;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    protected ?string $replacedBy = null;

    public function __construct()
    {
        $this->createdAt = new DateTimeImmutable();
    }

    /**
     * Get the user ID.
     * Must be implemented by child class based on ID strategy.
     */
    abstract public function getUserId(): string|int;

    /**
     * Set the user ID.
     * Must be implemented by child class based on ID strategy.
     */
    abstract public function setUserId(string|int $userId): static;

    public function getToken(): string
    {
        return $this->token;
    }

    public function setToken(string $token): static
    {
        $this->token = $token;

        return $this;
    }

    public function getExpiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(DateTimeImmutable $expiresAt): static
    {
        $this->expiresAt = $expiresAt;

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

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function setRevoked(bool $revoked): static
    {
        $this->revoked = $revoked;

        return $this;
    }

    public function getReplacedBy(): ?string
    {
        return $this->replacedBy;
    }

    public function setReplacedBy(?string $replacedBy): static
    {
        $this->replacedBy = $replacedBy;

        return $this;
    }

    /**
     * Check if the refresh token is valid (not expired and not revoked).
     */
    public function isValid(): bool
    {
        return !$this->revoked && $this->expiresAt > new DateTimeImmutable();
    }

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        if (!isset($this->createdAt)) {
            $this->createdAt = new DateTimeImmutable();
        }
    }
}
