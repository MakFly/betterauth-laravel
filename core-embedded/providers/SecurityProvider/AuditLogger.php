<?php

declare(strict_types=1);

namespace BetterAuth\Providers\SecurityProvider;

use BetterAuth\Core\Entities\SecurityEvent;
use Psr\Log\LoggerInterface;

final readonly class AuditLogger
{
    public function __construct(
        private SecurityMonitor $securityMonitor,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function logLoginSuccess(string $userId, ?string $ipAddress, ?string $userAgent): SecurityEvent
    {
        $event = $this->securityMonitor->logEvent(
            userId: $userId,
            eventType: 'login_success',
            severity: 'info',
            ipAddress: $ipAddress,
            userAgent: $userAgent,
        );

        $this->logger?->info("User {$userId} logged in successfully", [
            'ip' => $ipAddress,
            'user_agent' => $userAgent,
        ]);

        return $event;
    }

    public function logLoginFailure(string $email, ?string $ipAddress, ?string $userAgent, string $reason): void
    {
        $this->logger?->warning("Login failed for {$email}: {$reason}", [
            'ip' => $ipAddress,
            'user_agent' => $userAgent,
        ]);
    }

    public function logPasswordChange(string $userId, ?string $ipAddress): SecurityEvent
    {
        $event = $this->securityMonitor->logEvent(
            userId: $userId,
            eventType: 'password_changed',
            severity: 'warning',
            ipAddress: $ipAddress,
        );

        $this->logger?->warning("User {$userId} changed password", ['ip' => $ipAddress]);

        return $event;
    }

    public function logAccountLocked(string $userId, string $reason): SecurityEvent
    {
        $event = $this->securityMonitor->logEvent(
            userId: $userId,
            eventType: 'account_locked',
            severity: 'critical',
            details: ['reason' => $reason],
        );

        $this->logger?->critical("User {$userId} account locked: {$reason}");

        return $event;
    }

    public function logSuspiciousActivity(string $userId, string $activityType, ?string $ipAddress): SecurityEvent
    {
        $event = $this->securityMonitor->logEvent(
            userId: $userId,
            eventType: 'suspicious_activity',
            severity: 'warning',
            ipAddress: $ipAddress,
            details: ['activity_type' => $activityType],
        );

        $this->logger?->warning("Suspicious activity detected for user {$userId}: {$activityType}", [
            'ip' => $ipAddress,
        ]);

        return $event;
    }
}
