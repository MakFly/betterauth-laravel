<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\SessionActivity;

interface SessionActivityRepositoryInterface
{
    public function generateId(): ?string;

    public function create(array $data): SessionActivity;

    public function findById(string $id): ?SessionActivity;

    public function findBySessionId(string $sessionId, int $limit = 50): array;

    public function findByUserId(string $userId, int $limit = 100): array;

    public function delete(string $id): bool;

    public function deleteBySessionId(string $sessionId): int;
}
