<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\SuspiciousActivity;

interface SuspiciousActivityRepositoryInterface
{
    public function generateId(): ?string;

    public function create(array $data): SuspiciousActivity;

    public function findById(string $id): ?SuspiciousActivity;

    public function findByUserId(string $userId, int $limit = 100): array;

    public function findByStatus(string $status, int $limit = 100): array;

    public function update(string $id, array $data): SuspiciousActivity;

    public function delete(string $id): bool;
}
