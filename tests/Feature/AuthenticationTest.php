<?php

declare(strict_types=1);

use BetterAuth\Laravel\Facades\BetterAuth;
use Illuminate\Support\Facades\Event;
use BetterAuth\Laravel\Events\UserRegistered;
use BetterAuth\Laravel\Events\UserLoggedIn;
use BetterAuth\Laravel\Events\UserLoggedOut;

beforeEach(function () {
    $this->artisan('migrate', ['--database' => 'testing']);
});

describe('Registration', function () {
    it('registers a new user successfully', function () {
        Event::fake([UserRegistered::class]);

        $response = $this->postJson('/auth/register', [
            'email' => 'newuser@example.com',
            'password' => 'securepassword123',
            'name' => 'New User',
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'message',
                'user' => ['id', 'email', 'name'],
                'access_token',
                'refresh_token',
                'token_type',
                'expires_in',
            ])
            ->assertJson([
                'message' => 'Registration successful',
                'token_type' => 'Bearer',
            ]);

        Event::assertDispatched(UserRegistered::class);
    });

    it('fails registration with duplicate email', function () {
        $this->createTestUser(['email' => 'existing@example.com']);

        $response = $this->postJson('/auth/register', [
            'email' => 'existing@example.com',
            'password' => 'securepassword123',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    });

    it('fails registration with invalid email', function () {
        $response = $this->postJson('/auth/register', [
            'email' => 'not-an-email',
            'password' => 'securepassword123',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    });

    it('fails registration with short password', function () {
        $response = $this->postJson('/auth/register', [
            'email' => 'test@example.com',
            'password' => 'short',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);
    });
});

describe('Login', function () {
    it('logs in with valid credentials', function () {
        Event::fake([UserLoggedIn::class]);

        $this->createTestUser([
            'email' => 'user@example.com',
            'password' => password_hash('correctpassword', PASSWORD_ARGON2ID),
        ]);

        $response = $this->postJson('/auth/login', [
            'email' => 'user@example.com',
            'password' => 'correctpassword',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'user',
                'access_token',
                'refresh_token',
                'token_type',
                'expires_in',
            ]);

        expect($response->json('access_token'))->toBeValidToken();

        Event::assertDispatched(UserLoggedIn::class);
    });

    it('fails login with wrong password', function () {
        $this->createTestUser([
            'email' => 'user@example.com',
            'password' => password_hash('correctpassword', PASSWORD_ARGON2ID),
        ]);

        $response = $this->postJson('/auth/login', [
            'email' => 'user@example.com',
            'password' => 'wrongpassword',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    });

    it('fails login with non-existent user', function () {
        $response = $this->postJson('/auth/login', [
            'email' => 'nonexistent@example.com',
            'password' => 'anypassword',
        ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['email']);
    });
});

describe('Protected Routes', function () {
    it('gets current user with valid token', function () {
        $user = $this->createTestUser();

        $result = BetterAuth::signUp([
            'email' => 'tokentest@example.com',
            'password' => 'password123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->getJson('/auth/me');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'user' => ['id', 'email'],
            ]);
    });

    it('returns 401 without token', function () {
        $response = $this->getJson('/auth/me');

        $response->assertStatus(401);
    });

    it('returns 401 with invalid token', function () {
        $response = $this->withHeader('Authorization', 'Bearer invalid.token.here')
            ->getJson('/auth/me');

        $response->assertStatus(401);
    });
});

describe('Token Refresh', function () {
    it('refreshes token successfully', function () {
        $result = BetterAuth::signUp([
            'email' => 'refresh@example.com',
            'password' => 'password123',
        ]);

        $response = $this->postJson('/auth/refresh', [
            'refresh_token' => $result['refresh_token'],
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'message',
                'access_token',
                'refresh_token',
                'token_type',
                'expires_in',
            ]);

        // New token should be different (rotation)
        expect($response->json('refresh_token'))->not->toBe($result['refresh_token']);
    });

    it('fails with invalid refresh token', function () {
        $response = $this->postJson('/auth/refresh', [
            'refresh_token' => 'invalid-token',
        ]);

        $response->assertStatus(401)
            ->assertJson(['error' => 'token_invalid']);
    });

    it('fails with already used refresh token', function () {
        $result = BetterAuth::signUp([
            'email' => 'rotation@example.com',
            'password' => 'password123',
        ]);

        // First refresh
        $this->postJson('/auth/refresh', [
            'refresh_token' => $result['refresh_token'],
        ])->assertStatus(200);

        // Second refresh with same token should fail (one-time use)
        $this->postJson('/auth/refresh', [
            'refresh_token' => $result['refresh_token'],
        ])->assertStatus(401);
    });
});

describe('Logout', function () {
    it('logs out and revokes refresh token', function () {
        Event::fake([UserLoggedOut::class]);

        $result = BetterAuth::signUp([
            'email' => 'logout@example.com',
            'password' => 'password123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/logout', [
                'refresh_token' => $result['refresh_token'],
            ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Logged out successfully']);

        // Token should no longer be valid for refresh
        $this->postJson('/auth/refresh', [
            'refresh_token' => $result['refresh_token'],
        ])->assertStatus(401);

        Event::assertDispatched(UserLoggedOut::class);
    });
});

describe('Revoke All Tokens', function () {
    it('revokes all tokens for user', function () {
        $result = BetterAuth::signUp([
            'email' => 'revokeall@example.com',
            'password' => 'password123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->postJson('/auth/revoke-all');

        $response->assertStatus(200)
            ->assertJson(['message' => 'All tokens revoked']);
    });
});

describe('Password Update', function () {
    it('updates password with correct current password', function () {
        $result = BetterAuth::signUp([
            'email' => 'password@example.com',
            'password' => 'oldpassword123',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->putJson('/auth/password', [
                'current_password' => 'oldpassword123',
                'password' => 'newpassword456',
                'password_confirmation' => 'newpassword456',
            ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Password updated successfully']);

        // Should be able to login with new password
        $this->postJson('/auth/login', [
            'email' => 'password@example.com',
            'password' => 'newpassword456',
        ])->assertStatus(200);
    });

    it('fails with wrong current password', function () {
        $result = BetterAuth::signUp([
            'email' => 'wrongcurrent@example.com',
            'password' => 'correctpassword',
        ]);

        $response = $this->withHeader('Authorization', "Bearer {$result['access_token']}")
            ->putJson('/auth/password', [
                'current_password' => 'wrongpassword',
                'password' => 'newpassword456',
                'password_confirmation' => 'newpassword456',
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['current_password']);
    });
});
