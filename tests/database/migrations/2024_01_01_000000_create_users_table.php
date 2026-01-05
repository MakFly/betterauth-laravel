<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::dropIfExists('users');

        Schema::create('users', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email')->unique();
            $table->string('password')->nullable();
            $table->string('name')->nullable();
            $table->string('avatar', 500)->nullable();
            $table->json('roles')->default('["ROLE_USER"]');
            $table->timestamp('email_verified_at')->nullable();
            $table->rememberToken();
            $table->json('metadata')->nullable();
            $table->timestamps();
        });

        Schema::create('better_auth_refresh_tokens', function (Blueprint $table): void {
            $table->string('token', 64)->primary();
            $table->uuid('user_id');
            $table->timestamp('expires_at');
            $table->boolean('revoked')->default(false);
            $table->string('replaced_by', 64)->nullable();
            $table->timestamp('created_at');

            $table->index('user_id');
            $table->index(['user_id', 'revoked']);
        });

        Schema::create('better_auth_sessions', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('user_id');
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->string('device_type', 50)->nullable();
            $table->string('device_name', 255)->nullable();
            $table->string('location', 255)->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('last_activity_at');
            $table->timestamp('created_at');

            $table->index('user_id');
        });

        Schema::create('better_auth_magic_links', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('email');
            $table->string('token', 64)->unique();
            $table->timestamp('expires_at');
            $table->timestamp('used_at')->nullable();
            $table->timestamp('created_at');

            $table->index('email');
        });

        Schema::create('better_auth_totp_secrets', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('user_id')->unique();
            $table->string('secret', 64);
            $table->json('recovery_codes')->nullable();
            $table->boolean('enabled')->default(false);
            $table->timestamp('verified_at')->nullable();
            $table->timestamps();

            $table->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('better_auth_totp_secrets');
        Schema::dropIfExists('better_auth_magic_links');
        Schema::dropIfExists('better_auth_sessions');
        Schema::dropIfExists('better_auth_refresh_tokens');
        Schema::dropIfExists('users');
    }
};
