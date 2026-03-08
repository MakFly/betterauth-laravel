<?php

declare(strict_types=1);

namespace BetterAuth\Core\Plugin;

use BetterAuth\Core\Config\AuthConfig;

/**
 * Plugin context provides access to services, hooks, and configuration
 * for plugins during installation.
 *
 * This class acts as a service locator and hook registry for plugins.
 */
class PluginContext
{
    /**
     * @var array<string, callable[]> Hook callbacks
     */
    private array $hooks = [];

    /**
     * @var array<string, mixed> Services available to plugins
     */
    private array $services = [];

    public function __construct(
        private readonly AuthConfig $config,
    ) {
    }

    /**
     * Register a hook callback.
     *
     * Hooks allow plugins to react to events in the authentication flow.
     *
     * Available hooks:
     * - 'user.created' - After user is created
     * - 'user.logged_in' - After successful login
     * - 'user.logged_out' - After logout
     * - 'token.created' - After token is created
     * - 'session.created' - After session is created
     * - 'oauth.linked' - After OAuth account is linked
     *
     * @param string $hookName Name of the hook
     * @param callable $callback Callback to execute (receives event data)
     */
    public function registerHook(string $hookName, callable $callback): void
    {
        if (!isset($this->hooks[$hookName])) {
            $this->hooks[$hookName] = [];
        }

        $this->hooks[$hookName][] = $callback;
    }

    /**
     * Execute all callbacks registered for a hook.
     *
     * @param string $hookName Name of the hook to execute
     * @param mixed $data Data to pass to callbacks
     */
    public function executeHook(string $hookName, mixed $data): void
    {
        if (!isset($this->hooks[$hookName])) {
            return;
        }

        foreach ($this->hooks[$hookName] as $callback) {
            $callback($data);
        }
    }

    /**
     * Get all hooks.
     *
     * @return array<string, callable[]>
     */
    public function getHooks(): array
    {
        return $this->hooks;
    }

    /**
     * Register a service for use by plugins.
     *
     * @param string $name Service name
     * @param mixed $service Service instance
     */
    public function registerService(string $name, mixed $service): void
    {
        $this->services[$name] = $service;
    }

    /**
     * Get a registered service.
     *
     * @param string $name Service name
     *
     * @return mixed|null Service instance or null if not found
     */
    public function getService(string $name): mixed
    {
        return $this->services[$name] ?? null;
    }

    /**
     * Check if a service is registered.
     *
     * @param string $name Service name
     *
     * @return bool True if service exists
     */
    public function hasService(string $name): bool
    {
        return isset($this->services[$name]);
    }

    /**
     * Get the authentication configuration.
     */
    public function getConfig(): AuthConfig
    {
        return $this->config;
    }

    /**
     * Modify configuration (merge with existing).
     *
     * @param array<string, mixed> $config Configuration to merge
     */
    public function mergeConfig(array $config): void
    {
        // Note: AuthConfig is readonly, so this would require extending it
        // For now, this is a placeholder for framework-specific implementations
    }
}
