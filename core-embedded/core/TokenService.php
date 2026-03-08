<?php

declare(strict_types=1);

namespace BetterAuth\Core;

use BetterAuth\Core\Exceptions\InvalidTokenException;
use BetterAuth\Core\Exceptions\TokenExpiredException;
use BetterAuth\Core\Interfaces\TokenSignerInterface;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Rules\IssuedBy;
use ParagonIE\Paseto\Rules\NotExpired;

/**
 * Token service using official Paseto V4 library (paragonie/paseto).
 *
 * Paseto V4 provides:
 * - XChaCha20-Poly1305 encryption (256-bit)
 * - Ed25519 signatures
 * - Built-in expiration handling
 * - Cryptographically secure and audited implementation
 *
 * This service is final to ensure consistent token security behavior.
 */
final class TokenService implements TokenSignerInterface
{
    private const ISSUER = 'betterauth';

    private SymmetricKey $key;
    private readonly string $issuer;

    public function __construct(
        string $secretKey,
        string $issuer = self::ISSUER,
    ) {
        if (strlen($secretKey) < 32) {
            throw new \InvalidArgumentException('Secret key must be at least 32 characters');
        }

        $this->issuer = $issuer;

        // Create symmetric key from secret (32 bytes for V4) using HKDF for proper key derivation
        $keyMaterial = \BetterAuth\Core\Utils\Crypto::deriveKey($secretKey, 32, 'betterauth-token-key');
        $this->key = new SymmetricKey($keyMaterial);
    }

    /**
     * Sign a payload and create a Paseto V4 local token.
     */
    public function sign(array $payload, int $expiresIn): string
    {
        $now = new \DateTimeImmutable();
        $expiration = $now->modify("+{$expiresIn} seconds");

        $builder = Builder::getLocal($this->key, new Version4());

        // Set standard claims
        $builder
            ->setIssuedAt($now)
            ->setExpiration($expiration)
            ->setIssuer($this->issuer);

        // Set subject (user ID)
        if (isset($payload['sub'])) {
            $builder->setSubject((string) $payload['sub']);
        }

        // Set token type
        if (isset($payload['type'])) {
            $builder->setClaims(['type' => $payload['type']]);
        }

        // Set additional data
        if (isset($payload['data']) && is_array($payload['data'])) {
            $builder->setClaims(['data' => $payload['data']]);
        }

        // Add any other custom claims
        foreach ($payload as $key => $value) {
            if (!in_array($key, ['sub', 'type', 'data', 'iat', 'exp', 'iss'], true)) {
                $builder->setClaims([$key => $value]);
            }
        }

        return $builder->toString();
    }

    /**
     * Verify and decode a Paseto V4 token.
     *
     * @throws InvalidTokenException If token is invalid
     * @throws TokenExpiredException If token has expired
     */
    public function verify(string $token): ?array
    {
        try {
            $parser = Parser::getLocal($this->key, ProtocolCollection::v4())
                ->addRule(new NotExpired())
                ->addRule(new IssuedBy($this->issuer));

            $parsedToken = $parser->parse($token);
            $claims = $parsedToken->getClaims();

            // Convert to standard format
            return [
                'sub' => $claims['sub'] ?? '',
                'iat' => isset($claims['iat']) ? strtotime($claims['iat']) : time(),
                'exp' => isset($claims['exp']) ? strtotime($claims['exp']) : time(),
                'type' => $claims['type'] ?? 'access',
                'data' => $claims['data'] ?? null,
            ] + $claims;

        } catch (PasetoException $e) {
            // Check if it's an expiration error
            if (str_contains($e->getMessage(), 'expired') || str_contains($e->getMessage(), 'Expir')) {
                throw new TokenExpiredException('Token has expired');
            }

            return null;
        } catch (\Exception) {
            return null;
        }
    }

    /**
     * Decode a token without verification (for inspection only).
     * WARNING: Do not trust the data from this method for authentication!
     */
    public function decode(string $token): ?array
    {
        try {
            // Parse without validation rules to just decode
            $parser = Parser::getLocal($this->key, ProtocolCollection::v4());
            $parsedToken = $parser->parse($token);
            $claims = $parsedToken->getClaims();

            return [
                'sub' => $claims['sub'] ?? '',
                'iat' => isset($claims['iat']) ? strtotime($claims['iat']) : null,
                'exp' => isset($claims['exp']) ? strtotime($claims['exp']) : null,
                'type' => $claims['type'] ?? 'access',
                'data' => $claims['data'] ?? null,
            ] + $claims;

        } catch (\Exception) {
            return null;
        }
    }

    /**
     * Check if a token is expired without full verification.
     */
    public function isExpired(string $token): bool
    {
        $payload = $this->decode($token);
        if ($payload === null) {
            return true;
        }

        return isset($payload['exp']) && $payload['exp'] < time();
    }
}
