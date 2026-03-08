<?php

declare(strict_types=1);

namespace BetterAuth\Providers\DeviceManagementProvider;

/**
 * Geolocation service for IP address lookup.
 *
 * Note: This class is not final to allow mocking in tests.
 * In production, consider using a real geolocation provider.
 */
class GeolocationService
{
    public function getLocation(?string $ipAddress): ?string
    {
        if ($ipAddress === null || $this->isPrivateIP($ipAddress)) {
            return null;
        }

        return 'Unknown';
    }

    private function isPrivateIP(string $ip): bool
    {
        $privateRanges = [
            '10.0.0.0' => '10.255.255.255',
            '172.16.0.0' => '172.31.255.255',
            '192.168.0.0' => '192.168.255.255',
            '127.0.0.0' => '127.255.255.255',
        ];

        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return true;
        }

        foreach ($privateRanges as $start => $end) {
            if ($ipLong >= ip2long($start) && $ipLong <= ip2long($end)) {
                return true;
            }
        }

        return false;
    }
}
