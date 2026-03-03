<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Support;

use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Factory centralisant la création d'exceptions HTTP/API.
 *
 * Permet de garder des contrôleurs minces et cohérents.
 */
final class ApiExceptionFactory
{
    /**
     * Crée une ValidationException standard Laravel.
     *
     * @param  array<string, array<int, string>>  $errors
     */
    public function validation(array $errors): ValidationException
    {
        return ValidationException::withMessages($errors);
    }

    /**
     * Crée une exception HTTP 403.
     *
     * @param  string  $message  Message d'erreur métier
     */
    public function forbidden(string $message = 'Forbidden'): HttpException
    {
        return new HttpException(403, $message);
    }

    /**
     * Crée une exception HTTP 404.
     *
     * @param  string  $message  Message d'erreur métier
     */
    public function notFound(string $message = 'Not found'): HttpException
    {
        return new HttpException(404, $message);
    }

    /**
     * Crée une exception HTTP 502 pour erreur upstream.
     *
     * @param  string  $message  Message d'erreur métier
     */
    public function badGateway(string $message = 'Upstream provider temporarily unavailable.'): HttpException
    {
        return new HttpException(502, $message);
    }
}
