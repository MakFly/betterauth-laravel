<?php

declare(strict_types=1);

namespace BetterAuth\Core\Plugin\Events;

use BetterAuth\Core\Plugin\PluginInterface;

/**
 * Event dispatched when a plugin configuration is updated.
 */
class PluginConfiguredEvent
{
    /**
     * @param PluginInterface $plugin The configured plugin
     * @param array<string, mixed> $config New configuration
     * @param array<string, mixed> $previousConfig Previous configuration
     */
    public function __construct(
        public readonly PluginInterface $plugin,
        public readonly array $config,
        public readonly array $previousConfig = [],
    ) {
    }

    /**
     * Get the plugin name.
     */
    public function getPluginName(): string
    {
        return $this->plugin->getName();
    }

    /**
     * Get the new configuration.
     *
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Get the previous configuration.
     *
     * @return array<string, mixed>
     */
    public function getPreviousConfig(): array
    {
        return $this->previousConfig;
    }

    /**
     * Get configuration changes (keys that changed).
     *
     * @return array<string> Array of changed keys
     */
    public function getChangedKeys(): array
    {
        $changed = [];

        foreach ($this->config as $key => $value) {
            if (!isset($this->previousConfig[$key]) || $this->previousConfig[$key] !== $value) {
                $changed[] = $key;
            }
        }

        return $changed;
    }
}
