<?php

declare(strict_types=1);

namespace BetterAuth\Core\Interfaces;

use BetterAuth\Core\Entities\DeviceInfo;

interface DeviceInfoRepositoryInterface
{
    public function generateId(): ?string;

    public function create(array $data): DeviceInfo;

    public function findById(string $id): ?DeviceInfo;

    public function findByFingerprint(string $userId, string $fingerprint): ?DeviceInfo;

    public function findByUserId(string $userId): array;

    public function update(string $id, array $data): DeviceInfo;

    public function delete(string $id): bool;
}
