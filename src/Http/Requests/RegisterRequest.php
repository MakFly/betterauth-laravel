<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Validated registration request.
 */
final class RegisterRequest extends FormRequest
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
            'email' => ['required', 'string', 'email', 'unique:users,email'],
            'password' => ['required', 'string', 'min:8'],
            'name' => ['sometimes', 'string', 'max:255'],
        ];
    }
}
