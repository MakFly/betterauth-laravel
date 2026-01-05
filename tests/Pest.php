<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Test Case
|--------------------------------------------------------------------------
|
| The closure you provide to your test functions is always bound to a specific PHPUnit test
| case class. By default, that class is "PHPUnit\Framework\TestCase". Of course, you may
| need to change it using the "uses()" function to bind a different classes or traits.
|
*/

uses(BetterAuth\Laravel\Tests\TestCase::class)->in('Feature', 'Unit');

/*
|--------------------------------------------------------------------------
| Expectations
|--------------------------------------------------------------------------
|
| When you're writing tests, you often need to check that values meet certain conditions. The
| "expect()" function gives you access to a set of "expectations" methods that you can use
| to assert different things. Of course, you may extend the Expectation API at any time.
|
*/

expect()->extend('toBeValidToken', function () {
    return $this->toBeString()
        ->toStartWith('v4.local.');
});

expect()->extend('toBeValidUuid', function () {
    return $this->toBeString()
        ->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i');
});

/*
|--------------------------------------------------------------------------
| Functions
|--------------------------------------------------------------------------
|
| While Pest is very powerful out-of-the-box, you may have some testing code specific to your
| project that you don't want to repeat in every file. Here you can also expose helpers as
| global functions to help you to reduce the number of lines of code in your test files.
|
*/

function createUser(array $attributes = []): \Illuminate\Contracts\Auth\Authenticatable
{
    $userClass = config('betterauth.user_model', 'App\\Models\\User');

    return $userClass::factory()->create($attributes);
}

function createAuthenticatedRequest(string $token): \Illuminate\Http\Request
{
    $request = new \Illuminate\Http\Request();
    $request->headers->set('Authorization', "Bearer {$token}");

    return $request;
}
