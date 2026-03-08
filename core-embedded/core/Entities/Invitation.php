<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;

/**
 * Invitation entity for organization member invitations.
 * Manages secure onboarding with email verification and expiration.
 */
class Invitation
{
    public function __construct(
        public readonly string $id,
        public readonly string $organizationId,
        public readonly string $email,
        public readonly string $role,
        public readonly string $status,
        public readonly ?string $invitedBy = null,
        public readonly ?DateTimeImmutable $expiresAt = null,
        public readonly ?DateTimeImmutable $createdAt = null,
    ) {
    }

    /**
     * Create an Invitation entity from an array of data.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'] ?? '',
            organizationId: $data['organizationId'] ?? $data['organization_id'] ?? '',
            email: $data['email'] ?? '',
            role: $data['role'] ?? 'member',
            status: $data['status'] ?? 'pending',
            invitedBy: $data['invitedBy'] ?? $data['invited_by'] ?? null,
            expiresAt: isset($data['expiresAt'])
                ? ($data['expiresAt'] instanceof DateTimeImmutable
                    ? $data['expiresAt']
                    : new DateTimeImmutable($data['expiresAt']))
                : (isset($data['expires_at'])
                    ? ($data['expires_at'] instanceof DateTimeImmutable
                        ? $data['expires_at']
                        : new DateTimeImmutable($data['expires_at']))
                    : null),
            createdAt: isset($data['createdAt'])
                ? ($data['createdAt'] instanceof DateTimeImmutable
                    ? $data['createdAt']
                    : new DateTimeImmutable($data['createdAt']))
                : (isset($data['created_at'])
                    ? ($data['created_at'] instanceof DateTimeImmutable
                        ? $data['created_at']
                        : new DateTimeImmutable($data['created_at']))
                    : null),
        );
    }

    /**
     * Convert the entity to an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'organizationId' => $this->organizationId,
            'email' => $this->email,
            'role' => $this->role,
            'status' => $this->status,
            'invitedBy' => $this->invitedBy,
            'expiresAt' => $this->expiresAt?->format('Y-m-d H:i:s'),
            'createdAt' => $this->createdAt?->format('Y-m-d H:i:s'),
        ];
    }

    /**
     * Check if invitation is expired.
     */
    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt < new DateTimeImmutable();
    }

    /**
     * Check if invitation is pending.
     */
    public function isPending(): bool
    {
        return $this->status === 'pending' && !$this->isExpired();
    }

    /**
     * Check if invitation is accepted.
     */
    public function isAccepted(): bool
    {
        return $this->status === 'accepted';
    }

    /**
     * Check if invitation is rejected.
     */
    public function isRejected(): bool
    {
        return $this->status === 'rejected';
    }

    /**
     * Check if invitation is cancelled.
     */
    public function isCancelled(): bool
    {
        return $this->status === 'cancelled';
    }
}
