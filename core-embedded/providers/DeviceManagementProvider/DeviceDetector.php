<?php

declare(strict_types=1);

namespace BetterAuth\Providers\DeviceManagementProvider;

/**
 * Device detector for extracting device information from user agents.
 *
 * This service is final to ensure consistent device detection behavior.
 */
final class DeviceDetector
{
    public function detect(?string $userAgent): array
    {
        if ($userAgent === null) {
            return $this->getDefaultDeviceInfo();
        }

        return [
            'device_type' => $this->detectDeviceType($userAgent),
            'browser' => $this->detectBrowser($userAgent),
            'browser_version' => $this->detectBrowserVersion($userAgent),
            'os' => $this->detectOS($userAgent),
            'os_version' => $this->detectOSVersion($userAgent),
        ];
    }

    private function detectDeviceType(string $userAgent): string
    {
        if (preg_match('/(tablet|ipad|playbook)|(android(?!.*mobile))/i', $userAgent)) {
            return 'tablet';
        }
        if (preg_match('/Mobile|Android|iP(hone|od)|IEMobile|BlackBerry|Kindle|Silk-Accelerated|(hpw|web)OS|Opera M(obi|ini)/i', $userAgent)) {
            return 'mobile';
        }

        return 'desktop';
    }

    private function detectBrowser(string $userAgent): ?string
    {
        $browsers = [
            'Chrome' => '/Chrome\/[\d.]+/i',
            'Firefox' => '/Firefox\/[\d.]+/i',
            'Safari' => '/Safari\/[\d.]+/i',
            'Edge' => '/Edg\/[\d.]+/i',
            'Opera' => '/OPR\/[\d.]+/i',
        ];

        foreach ($browsers as $name => $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return $name;
            }
        }

        return null;
    }

    private function detectBrowserVersion(string $userAgent): ?string
    {
        if (preg_match('/(Chrome|Firefox|Safari|Edg|OPR)\/([\d.]+)/i', $userAgent, $matches)) {
            return $matches[2];
        }

        return null;
    }

    private function detectOS(string $userAgent): ?string
    {
        $os = [
            'iOS' => '/iPhone|iPad|iPod/i',
            'Android' => '/Android/i',
            'Windows' => '/Windows NT/i',
            'macOS' => '/Mac OS X/i',
            'Linux' => '/Linux/i',
        ];

        foreach ($os as $name => $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return $name;
            }
        }

        return null;
    }

    private function detectOSVersion(string $userAgent): ?string
    {
        if (preg_match('/Windows NT ([\d.]+)/i', $userAgent, $matches)) {
            return $matches[1];
        }
        if (preg_match('/Mac OS X ([\d_]+)/i', $userAgent, $matches)) {
            return str_replace('_', '.', $matches[1]);
        }
        if (preg_match('/Android ([\d.]+)/i', $userAgent, $matches)) {
            return $matches[1];
        }
        if (preg_match('/OS ([\d_]+)/i', $userAgent, $matches)) {
            return str_replace('_', '.', $matches[1]);
        }

        return null;
    }

    private function getDefaultDeviceInfo(): array
    {
        return [
            'device_type' => 'unknown',
            'browser' => null,
            'browser_version' => null,
            'os' => null,
            'os_version' => null,
        ];
    }
}
