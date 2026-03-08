<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use Doctrine\ORM\Mapping as ORM;

#[ORM\MappedSuperclass]
class TotpData
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', unique: true)]
    private string $userId;

    #[ORM\Column(type: 'string')]
    private string $secret;

    #[ORM\Column(type: 'boolean')]
    private bool $enabled = false;

    #[ORM\Column(type: 'json')]
    private array $backupCodes = [];

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $last2faVerifiedAt = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUserId(): string
    {
        return $this->userId;
    }

    public function setUserId(string $userId): self
    {
        $this->userId = $userId;

        return $this;
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function setSecret(string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function setEnabled(bool $enabled): self
    {
        $this->enabled = $enabled;

        return $this;
    }

    public function getBackupCodes(): array
    {
        return $this->backupCodes;
    }

    public function setBackupCodes(array $backupCodes): self
    {
        $this->backupCodes = $backupCodes;

        return $this;
    }

    public function getLast2faVerifiedAt(): ?\DateTimeImmutable
    {
        return $this->last2faVerifiedAt;
    }

    public function setLast2faVerifiedAt(?\DateTimeImmutable $last2faVerifiedAt): self
    {
        $this->last2faVerifiedAt = $last2faVerifiedAt;

        return $this;
    }
}
