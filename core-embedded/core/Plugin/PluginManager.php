<?php

declare(strict_types=1);

namespace BetterAuth\Core\Plugin;

use BetterAuth\Core\Config\AuthConfig;
use BetterAuth\Core\Plugin\Events\PluginLoadedEvent;

/**
 * Plugin Manager handles loading, configuring, and managing plugins.
 *
 * Usage:
 * ```php
 * $manager = new PluginManager($config);
 * $manager->register(new AccountLinkingPlugin());
 * $manager->register(new GuestSessionPlugin());
 * $manager->loadAll();
 *
 * // Execute hooks
 * $manager->executeHook('user.created', $user);
 * ```
 */
class PluginManager
{
    /**
     * @var array<string, PluginInterface> Registered plugins
     */
    private array $plugins = [];

    /**
     * @var array<string, PluginInterface> Loaded plugins
     */
    private array $loadedPlugins = [];

    private readonly PluginContext $context;

    /**
     * @var callable|null Event dispatcher (optional)
     */
    private $eventDispatcher = null;

    public function __construct(
        AuthConfig $config,
    ) {
        $this->context = new PluginContext($config);
    }

    /**
     * Register a plugin.
     *
     * @param PluginInterface $plugin Plugin to register
     *
     * @throws \RuntimeException If plugin with same name already registered
     */
    public function register(PluginInterface $plugin): void
    {
        $name = $plugin->getName();

        if (isset($this->plugins[$name])) {
            throw new \RuntimeException("Plugin '$name' is already registered");
        }

        $this->plugins[$name] = $plugin;
    }

    /**
     * Unregister a plugin.
     *
     * @param string $pluginName Name of plugin to unregister
     */
    public function unregister(string $pluginName): void
    {
        unset($this->plugins[$pluginName]);
        unset($this->loadedPlugins[$pluginName]);
    }

    /**
     * Load a specific plugin.
     *
     * @param string $pluginName Name of plugin to load
     *
     * @throws \RuntimeException If plugin not found or dependencies not met
     */
    public function load(string $pluginName): void
    {
        if (!isset($this->plugins[$pluginName])) {
            throw new \RuntimeException("Plugin '$pluginName' is not registered");
        }

        if (isset($this->loadedPlugins[$pluginName])) {
            return; // Already loaded
        }

        $plugin = $this->plugins[$pluginName];

        if (!$plugin->isEnabled()) {
            return; // Plugin is disabled
        }

        // Check dependencies
        foreach ($plugin->getDependencies() as $dependency) {
            if (!isset($this->loadedPlugins[$dependency])) {
                // Try to load dependency first
                $this->load($dependency);
            }
        }

        // Install plugin
        $plugin->install($this->context);

        $this->loadedPlugins[$pluginName] = $plugin;

        // Dispatch event
        $this->dispatchEvent(new PluginLoadedEvent($plugin));
    }

    /**
     * Load all registered plugins.
     */
    public function loadAll(): void
    {
        foreach (array_keys($this->plugins) as $pluginName) {
            try {
                $this->load($pluginName);
            } catch (\RuntimeException $e) {
                // Log error but continue loading other plugins
                error_log("Failed to load plugin '$pluginName': " . $e->getMessage());
            }
        }
    }

    /**
     * Get a loaded plugin by name.
     *
     * @param string $pluginName Plugin name
     *
     * @return PluginInterface|null Plugin instance or null if not loaded
     */
    public function getPlugin(string $pluginName): ?PluginInterface
    {
        return $this->loadedPlugins[$pluginName] ?? null;
    }

    /**
     * Get all loaded plugins.
     *
     * @return array<string, PluginInterface>
     */
    public function getLoadedPlugins(): array
    {
        return $this->loadedPlugins;
    }

    /**
     * Get all registered plugins (loaded or not).
     *
     * @return array<string, PluginInterface>
     */
    public function getAllPlugins(): array
    {
        return $this->plugins;
    }

    /**
     * Check if a plugin is loaded.
     *
     * @param string $pluginName Plugin name
     *
     * @return bool True if loaded
     */
    public function isLoaded(string $pluginName): bool
    {
        return isset($this->loadedPlugins[$pluginName]);
    }

    /**
     * Execute a hook with data.
     *
     * This delegates to the PluginContext to execute all callbacks
     * registered for the given hook.
     *
     * @param string $hookName Hook name
     * @param mixed $data Data to pass to callbacks
     */
    public function executeHook(string $hookName, mixed $data): void
    {
        $this->context->executeHook($hookName, $data);
    }

    /**
     * Get the plugin context.
     */
    public function getContext(): PluginContext
    {
        return $this->context;
    }

    /**
     * Set an event dispatcher for plugin events.
     *
     * @param callable $dispatcher Function to dispatch events
     */
    public function setEventDispatcher(callable $dispatcher): void
    {
        $this->eventDispatcher = $dispatcher;
    }

    /**
     * Dispatch a plugin event.
     *
     * @param object $event Event object
     */
    private function dispatchEvent(object $event): void
    {
        if ($this->eventDispatcher !== null) {
            ($this->eventDispatcher)($event);
        }
    }
}
