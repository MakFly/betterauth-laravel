<?php

declare(strict_types=1);

namespace BetterAuth\Core\Entities;

use DateTimeImmutable;
use Doctrine\ORM\Mapping as ORM;

/**
 * Email Verification Token entity.
 */
#[ORM\MappedSuperclass]
class EmailVerificationToken extends BaseToken
{
    public static function fromArray(array $data): self
    {
        $token = new self();
        $token->setToken($data['token']);
        $token->setEmail($data['email']);
        $token->setExpiresAt(new DateTimeImmutable($data['expires_at']));
        $token->setCreatedAt(new DateTimeImmutable($data['created_at'] ?? 'now'));
        $token->setUsed($data['used'] ?? false);

        return $token;
    }

    public function toArray(): array
    {
        return [
            'token' => $this->token,
            'email' => $this->email,
            'expires_at' => $this->expiresAt->format('Y-m-d H:i:s'),
            'created_at' => $this->createdAt->format('Y-m-d H:i:s'),
            'used' => $this->used,
        ];
    }
}
