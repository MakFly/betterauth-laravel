<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::dropIfExists('better_auth_oauth_accounts');

        Schema::create('better_auth_oauth_accounts', function (Blueprint $table): void {
            $table->id();
            $table->uuid('user_id');
            $table->string('provider'); // google, github, facebook, etc.
            $table->string('provider_user_id');
            $table->string('provider_email')->nullable();
            $table->string('access_token')->nullable();
            $table->string('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->json('raw_data')->nullable();
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->unique(['provider', 'provider_user_id']);
            $table->index('user_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('better_auth_oauth_accounts');
    }
};
