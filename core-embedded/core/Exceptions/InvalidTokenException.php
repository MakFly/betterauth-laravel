<?php

declare(strict_types=1);

namespace BetterAuth\Core\Exceptions;

/**
 * Exception thrown when a token is invalid or expired.
 *
 * This exception is final to prevent over-specialization of token errors.
 */
final class InvalidTokenException extends AuthException
{
    public function __construct(string $message = 'Invalid or expired token')
    {
        parent::__construct($message, 401);
    }
}
