<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\GuestSession;

interface GuestSessionRepositoryInterface
{
    public function generateId(): ?string;

    public function create(array $data): GuestSession;

    public function findById(string $id): ?GuestSession;

    public function findByToken(string $token): ?GuestSession;

    public function delete(string $id): bool;

    public function deleteExpired(): int;
}
