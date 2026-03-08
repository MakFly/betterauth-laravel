<?php

declare(strict_types=1);

namespace BetterAuth\Core\Utils;

use BetterAuth\Core\Interfaces\RateLimiterInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Rate limiter implementation with optional persistent cache support.
 *
 * For production use, provide a PSR-6 cache implementation (Redis, Memcached, APCu).
 * Without cache, falls back to in-memory storage (not recommended for production).
 *
 * This service is final to ensure consistent rate limiting behavior.
 */
final class RateLimiter implements RateLimiterInterface
{
    private const CACHE_PREFIX = 'better_auth.rate_limit.';

    /** @var array<string, array{attempts: int, reset: int}> */
    private array $memoryStorage = [];

    public function __construct(
        private readonly ?CacheItemPoolInterface $cache = null,
    ) {
    }

    public function tooManyAttempts(string $key, int $maxAttempts, int $decaySeconds): bool
    {
        $data = $this->getData($key);

        if ($data === null) {
            return false;
        }

        if ($data['reset'] <= time()) {
            $this->clear($key);
            return false;
        }

        return $data['attempts'] >= $maxAttempts;
    }

    public function hit(string $key, int $decaySeconds): int
    {
        $now = time();
        $data = $this->getData($key);

        if ($data === null || $data['reset'] <= $now) {
            $data = [
                'attempts' => 0,
                'reset' => $now + $decaySeconds,
            ];
        }

        $data['attempts']++;

        $this->saveData($key, $data, $decaySeconds);

        return $data['attempts'];
    }

    public function attempts(string $key): int
    {
        $data = $this->getData($key);

        if ($data === null) {
            return 0;
        }

        if ($data['reset'] <= time()) {
            $this->clear($key);
            return 0;
        }

        return $data['attempts'];
    }

    public function clear(string $key): bool
    {
        if ($this->cache !== null) {
            return $this->cache->deleteItem($this->getCacheKey($key));
        }

        if (isset($this->memoryStorage[$key])) {
            unset($this->memoryStorage[$key]);
            return true;
        }

        return false;
    }

    public function availableIn(string $key): int
    {
        $data = $this->getData($key);

        if ($data === null) {
            return 0;
        }

        $availableIn = $data['reset'] - time();

        if ($availableIn <= 0) {
            $this->clear($key);
            return 0;
        }

        return $availableIn;
    }

    /**
     * Get rate limit data from cache or memory.
     *
     * @return array{attempts: int, reset: int}|null
     */
    private function getData(string $key): ?array
    {
        // Use cache if available
        if ($this->cache !== null) {
            $item = $this->cache->getItem($this->getCacheKey($key));
            if ($item->isHit()) {
                $data = $item->get();
                if (is_array($data) && isset($data['attempts'], $data['reset'])) {
                    return $data;
                }
            }
            return null;
        }

        // Fallback to in-memory storage
        if (isset($this->memoryStorage[$key]) && $this->memoryStorage[$key]['reset'] >= time()) {
            return $this->memoryStorage[$key];
        }

        // Clean up expired memory entries
        unset($this->memoryStorage[$key]);

        return null;
    }

    /**
     * Save rate limit data to cache or memory.
     *
     * @param array{attempts: int, reset: int} $data
     */
    private function saveData(string $key, array $data, int $decaySeconds): void
    {
        if ($this->cache !== null) {
            $item = $this->cache->getItem($this->getCacheKey($key));
            $item->set($data);
            $item->expiresAfter($decaySeconds);
            $this->cache->save($item);
            return;
        }

        // Fallback to in-memory storage
        $this->memoryStorage[$key] = $data;
    }

    private function getCacheKey(string $key): string
    {
        return self::CACHE_PREFIX . hash('sha256', $key);
    }
}
