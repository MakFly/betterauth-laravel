<?php

declare(strict_types=1);

namespace BetterAuth\Providers\GuestSessionProvider;

use BetterAuth\Core\Entities\GuestSession;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Interfaces\GuestSessionRepositoryInterface;
use BetterAuth\Core\Interfaces\UserRepositoryInterface;
use BetterAuth\Core\Utils\IdGenerator;
use DateTimeImmutable;

final readonly class GuestSessionProvider
{
    public function __construct(
        private GuestSessionRepositoryInterface $guestSessionRepository,
        private UserRepositoryInterface $userRepository,
        private int $sessionLifetime = 86400,
    ) {
    }

    public function createGuestSession(?string $deviceInfo = null, ?string $ipAddress = null, ?array $metadata = null): GuestSession
    {
        $id = $this->guestSessionRepository->generateId() ?? IdGenerator::ulid();
        $token = bin2hex(random_bytes(32));
        $createdAt = new DateTimeImmutable();
        $expiresAt = $createdAt->modify("+{$this->sessionLifetime} seconds");

        return $this->guestSessionRepository->create([
            'id' => $id,
            'token' => $token,
            'device_info' => $deviceInfo,
            'ip_address' => $ipAddress,
            'created_at' => $createdAt->format('Y-m-d H:i:s'),
            'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
            'metadata' => $metadata,
        ]);
    }

    public function convertToUser(string $guestToken, array $userData): User
    {
        $guestSession = $this->guestSessionRepository->findByToken($guestToken);
        if ($guestSession === null) {
            throw new \RuntimeException('Guest session not found');
        }

        $now = new DateTimeImmutable();
        $expiresAt = new DateTimeImmutable($guestSession->expiresAt);
        if ($expiresAt < $now) {
            throw new \RuntimeException('Guest session has expired');
        }

        $userId = $this->userRepository->generateId() ?? IdGenerator::ulid();
        $user = $this->userRepository->create(array_merge($userData, ['id' => $userId]));

        $this->guestSessionRepository->delete($guestSession->id);

        return $user;
    }

    public function getGuestSession(string $token): ?GuestSession
    {
        return $this->guestSessionRepository->findByToken($token);
    }

    public function deleteGuestSession(string $id): bool
    {
        return $this->guestSessionRepository->delete($id);
    }

    public function cleanupExpiredSessions(): int
    {
        return $this->guestSessionRepository->deleteExpired();
    }
}
