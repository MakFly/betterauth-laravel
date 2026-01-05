<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::dropIfExists('better_auth_refresh_tokens');

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
    }

    public function down(): void
    {
        Schema::dropIfExists('better_auth_refresh_tokens');
    }
};
