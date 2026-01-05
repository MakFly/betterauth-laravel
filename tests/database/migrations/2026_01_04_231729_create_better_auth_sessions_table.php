<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::dropIfExists('better_auth_sessions');

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
            $table->index(['user_id', 'expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('better_auth_sessions');
    }
};
