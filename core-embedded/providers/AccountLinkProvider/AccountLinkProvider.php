<?php

declare(strict_types=1);

namespace BetterAuth\Providers\AccountLinkProvider;

use BetterAuth\Core\Entities\AccountLink;
use BetterAuth\Core\Entities\User;
use BetterAuth\Core\Interfaces\AccountLinkRepositoryInterface;
use BetterAuth\Core\Utils\IdGenerator;
use DateTimeImmutable;

final readonly class AccountLinkProvider
{
    public function __construct(
        private AccountLinkRepositoryInterface $accountLinkRepository,
    ) {
    }

    public function linkAccount(
        User $user,
        string $provider,
        string $providerId,
        ?string $providerEmail = null,
        ?array $metadata = null,
    ): AccountLink {
        if ($this->accountLinkRepository->isLinked($user->getId(), $provider)) {
            throw new \RuntimeException("Provider '$provider' is already linked to this user");
        }

        $existingLink = $this->accountLinkRepository->findByProvider($provider, $providerId);
        if ($existingLink !== null && $existingLink->userId !== $user->getId()) {
            throw new \RuntimeException('This provider account is already linked to another user');
        }

        $id = $this->accountLinkRepository->generateId() ?? IdGenerator::ulid();
        $isPrimary = $this->accountLinkRepository->countForUser($user->getId()) === 0;

        return $this->accountLinkRepository->create([
            'id' => $id,
            'user_id' => $user->getId(),
            'provider' => $provider,
            'provider_id' => $providerId,
            'provider_email' => $providerEmail,
            'is_primary' => $isPrimary,
            'status' => 'verified',
            'linked_at' => (new DateTimeImmutable())->format('Y-m-d H:i:s'),
            'metadata' => $metadata,
        ]);
    }

    public function unlinkAccount(string $userId, string $provider): bool
    {
        $link = $this->accountLinkRepository->findByUserAndProvider($userId, $provider);
        if ($link === null) {
            return false;
        }

        $linkCount = $this->accountLinkRepository->countForUser($userId);
        if ($linkCount === 1) {
            throw new \RuntimeException('Cannot unlink the only authentication method');
        }

        return $this->accountLinkRepository->delete($link->id);
    }

    public function setPrimary(string $userId, string $provider): bool
    {
        return $this->accountLinkRepository->setPrimary($userId, $provider);
    }

    public function getAccountLinks(string $userId): array
    {
        return $this->accountLinkRepository->findByUserId($userId);
    }

    public function findUserByProvider(string $provider, string $providerId): ?string
    {
        $link = $this->accountLinkRepository->findByProvider($provider, $providerId);

        return $link?->userId;
    }
}
