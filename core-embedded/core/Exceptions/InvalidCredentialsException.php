<?php

declare(strict_types=1);

namespace BetterAuth\Core\Exceptions;

/**
 * Exception thrown when credentials are invalid.
 *
 * This exception is final to prevent over-specialization of credential errors.
 */
final class InvalidCredentialsException extends AuthException
{
    public function __construct(string $message = 'Invalid credentials')
    {
        parent::__construct($message, 401);
    }
}
