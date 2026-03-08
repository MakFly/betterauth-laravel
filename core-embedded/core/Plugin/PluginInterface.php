<?php

declare(strict_types=1);

namespace BetterAuth\Core\Plugin;

/**
 * Plugin interface for extending BetterAuth functionality.
 *
 * Plugins can add new features, modify existing behavior, and provide hooks
 * for customization without modifying core code.
 *
 * Example usage:
 * ```php
 * class MyCustomPlugin implements PluginInterface {
 *     public function getName(): string {
 *         return 'my-custom-plugin';
 *     }
 *
 *     public function install(PluginContext $context): void {
 *         // Register hooks, modify configuration, etc.
 *         $context->registerHook('user.created', fn($user) => ...);
 *     }
 *
 *     public function getConfig(): array {
 *         return ['enabled' => true, 'custom_option' => 'value'];
 *     }
 * }
 * ```
 */
interface PluginInterface
{
    /**
     * Get the unique name/identifier of the plugin.
     *
     * @return string Unique plugin name (e.g., 'account-linking', 'guest-sessions')
     */
    public function getName(): string;

    /**
     * Install the plugin and register its hooks/services.
     *
     * This method is called when the plugin is loaded by the PluginManager.
     * Use the PluginContext to register hooks, modify configuration, and access services.
     *
     * @param PluginContext $context The plugin context with access to services and hooks
     */
    public function install(PluginContext $context): void;

    /**
     * Get the plugin configuration.
     *
     * @return array<string, mixed> Configuration array
     */
    public function getConfig(): array;

    /**
     * Get the plugin version.
     *
     * @return string Version (e.g., '1.0.0')
     */
    public function getVersion(): string;

    /**
     * Get plugin dependencies (other plugins required).
     *
     * @return array<string> Array of plugin names this plugin depends on
     */
    public function getDependencies(): array;

    /**
     * Check if the plugin is enabled.
     *
     * @return bool True if enabled, false otherwise
     */
    public function isEnabled(): bool;
}
