<?php

declare(strict_types=1);

namespace BetterAuth\Core\Exceptions;

/**
 * Exception thrown when rate limit is exceeded.
 *
 * This exception is final to prevent over-specialization of rate limit errors.
 */
final class RateLimitException extends AuthException
{
    public function __construct(
        string $message = 'Too many attempts. Please try again later.',
        public readonly int $retryAfter = 60,
    ) {
        parent::__construct($message, 429);
    }
}
