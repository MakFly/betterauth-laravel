<?php

declare(strict_types=1);

namespace BetterAuth\Laravel\Support;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Factory de réponses JSON API.
 *
 * - Uniformise le shape des réponses
 * - Ajoute des headers de sécurité (no-store)
 * - Retourne application/problem+json quand le client API Platform le demande
 */
final class ApiResponseFactory
{
    /**
     * @param  array<string, mixed>  $payload
     * @param  array<string, string>  $headers
     */
    public function json(
        array $payload,
        int $status = 200,
        ?Request $request = null,
        array $headers = [],
        bool $noStore = false,
    ): JsonResponse {
        $resolvedHeaders = $headers;

        if ($noStore) {
            $resolvedHeaders = array_merge([
                'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
                'Pragma' => 'no-cache',
                'Referrer-Policy' => 'no-referrer',
            ], $resolvedHeaders);
        }

        if ($request !== null && $this->expectsProblemJson($request) && $status >= 400) {
            $problem = [
                'type' => 'about:blank',
                'title' => $payload['message'] ?? 'Request failed',
                'status' => $status,
                'detail' => $payload['message'] ?? 'Request failed',
            ];

            if (isset($payload['error']) && is_string($payload['error'])) {
                $problem['error'] = $payload['error'];
            }

            if (isset($payload['errors']) && is_array($payload['errors'])) {
                $problem['violations'] = $payload['errors'];
            }

            $resolvedHeaders['Content-Type'] = 'application/problem+json';

            return response()->json($problem, $status, $resolvedHeaders);
        }

        return response()->json($payload, $status, $resolvedHeaders);
    }

    /**
     * Réponse 200.
     *
     * @param  array<string, mixed>  $payload
     * @param  Request|null  $request  Requête HTTP courante
     * @param  bool  $noStore  Active les headers anti-cache
     */
    public function ok(array $payload, ?Request $request = null, bool $noStore = false): JsonResponse
    {
        return $this->json($payload, 200, $request, noStore: $noStore);
    }

    /**
     * Réponse 201.
     *
     * @param  array<string, mixed>  $payload
     * @param  Request|null  $request  Requête HTTP courante
     * @param  bool  $noStore  Active les headers anti-cache
     */
    public function created(array $payload, ?Request $request = null, bool $noStore = false): JsonResponse
    {
        return $this->json($payload, 201, $request, noStore: $noStore);
    }

    /**
     * @param  array<string, mixed>  $extra
     * @param  string  $message  Message lisible client
     * @param  string  $error  Code d'erreur stable
     * @param  int  $status  HTTP status code
     * @param  Request|null  $request  Requête HTTP courante
     * @param  bool  $noStore  Active les headers anti-cache
     */
    public function error(
        string $message,
        string $error,
        int $status,
        ?Request $request = null,
        array $extra = [],
        bool $noStore = false,
    ): JsonResponse {
        return $this->json(
            array_merge([
                'message' => $message,
                'error' => $error,
            ], $extra),
            $status,
            $request,
            noStore: $noStore,
        );
    }

    public function unauthenticated(?Request $request = null): JsonResponse
    {
        return $this->error('Unauthenticated', 'unauthenticated', 401, $request);
    }

    /**
     * Détecte si le client souhaite un format orienté API Platform.
     *
     * @param  Request  $request  Requête HTTP
     */
    private function expectsProblemJson(Request $request): bool
    {
        $accept = strtolower((string) $request->header('accept', ''));

        return str_contains($accept, 'application/problem+json')
            || str_contains($accept, 'application/ld+json');
    }
}
