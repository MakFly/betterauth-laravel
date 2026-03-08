<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\SecurityEvent;

interface SecurityEventRepositoryInterface
{
    public function generateId(): ?string;

    public function create(array $data): SecurityEvent;

    public function findById(string $id): ?SecurityEvent;

    public function findByUserId(string $userId, int $limit = 100): array;

    public function findBySeverity(string $severity, int $limit = 100): array;

    public function delete(string $id): bool;
}
