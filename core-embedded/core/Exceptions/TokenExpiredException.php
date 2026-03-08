<?php

declare(strict_types=1);

namespace BetterAuth\Core\Exceptions;

/**
 * Exception thrown when a token has expired.
 */
class TokenExpiredException extends AuthException
{
    private ?\DateTimeImmutable $expiredAt;

    public function __construct(
        string $message = 'Token has expired',
        ?\DateTimeImmutable $expiredAt = null,
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
        $this->expiredAt = $expiredAt;
    }

    public function getExpiredAt(): ?\DateTimeImmutable
    {
        return $this->expiredAt;
    }
}
