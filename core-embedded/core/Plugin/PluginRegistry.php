<?php

declare(strict_types=1);

namespace BetterAuth\Core\Plugin;

/**
 * Plugin Registry for auto-discovery and registration of plugins.
 *
 * This class provides utilities to discover and register plugins automatically,
 * either from a directory or via explicit registration.
 */
class PluginRegistry
{
    /**
     * @var array<class-string<PluginInterface>> Registered plugin classes
     */
    private array $pluginClasses = [];

    /**
     * Register a plugin class for auto-instantiation.
     *
     * @param class-string<PluginInterface> $pluginClass Fully qualified plugin class name
     *
     * @throws \InvalidArgumentException If class doesn't implement PluginInterface
     */
    public function registerClass(string $pluginClass): void
    {
        if (!class_exists($pluginClass)) {
            throw new \InvalidArgumentException("Plugin class '$pluginClass' does not exist");
        }

        if (!is_subclass_of($pluginClass, PluginInterface::class)) {
            throw new \InvalidArgumentException(
                "Plugin class '$pluginClass' must implement " . PluginInterface::class,
            );
        }

        $this->pluginClasses[] = $pluginClass;
    }

    /**
     * Get all registered plugin classes.
     *
     * @return array<class-string<PluginInterface>>
     */
    public function getPluginClasses(): array
    {
        return $this->pluginClasses;
    }

    /**
     * Create plugin instances from registered classes.
     *
     * @param array<string, mixed> $constructorArgs Optional constructor arguments
     *
     * @return array<PluginInterface> Array of plugin instances
     */
    public function createInstances(array $constructorArgs = []): array
    {
        $instances = [];

        foreach ($this->pluginClasses as $pluginClass) {
            try {
                // Try to instantiate with provided args
                if (!empty($constructorArgs)) {
                    $instances[] = new $pluginClass(...$constructorArgs);
                } else {
                    $instances[] = new $pluginClass();
                }
            } catch (\Throwable $e) {
                // Log error and skip this plugin (catches both Exceptions and Errors)
                error_log("Failed to instantiate plugin '$pluginClass': " . $e->getMessage());
            }
        }

        return $instances;
    }

    /**
     * Discover plugin classes in a directory.
     *
     * This method scans a directory for PHP files and looks for classes
     * implementing PluginInterface.
     *
     * @param string $directory Directory to scan
     * @param string $namespace Base namespace for discovered classes
     */
    public function discoverFromDirectory(string $directory, string $namespace): void
    {
        if (!is_dir($directory)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            // Extract class name from file path
            $relativePath = str_replace($directory . '/', '', $file->getPathname());
            $className = $namespace . '\\' . str_replace(
                ['/', '.php'],
                ['\\', ''],
                $relativePath,
            );

            // Try to register the class
            try {
                $this->registerClass($className);
            } catch (\InvalidArgumentException $e) {
                // Skip non-plugin classes
                continue;
            }
        }
    }

    /**
     * Register multiple plugin classes at once.
     *
     * @param array<class-string<PluginInterface>> $pluginClasses Array of plugin class names
     */
    public function registerMany(array $pluginClasses): void
    {
        foreach ($pluginClasses as $pluginClass) {
            $this->registerClass($pluginClass);
        }
    }

    /**
     * Clear all registered plugin classes.
     */
    public function clear(): void
    {
        $this->pluginClasses = [];
    }
}
