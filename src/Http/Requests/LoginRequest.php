<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Validated login request.
 */
final class LoginRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, array<string>>
     */
    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string', 'min:8'],
        ];
    }
}
