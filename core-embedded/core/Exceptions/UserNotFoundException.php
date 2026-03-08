<?php

declare(strict_types=1);

namespace BetterAuth\Core\Exceptions;

/**
 * Exception thrown when a user is not found.
 *
 * This exception is final to prevent over-specialization of user lookup errors.
 */
final class UserNotFoundException extends AuthException
{
    public function __construct(string $message = 'User not found')
    {
        parent::__construct($message, 404);
    }
}
