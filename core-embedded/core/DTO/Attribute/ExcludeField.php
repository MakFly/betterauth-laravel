<?php

declare(strict_types=1);

namespace BetterAuth\Core\DTO\Attribute;

use Attribute;

/**
 * Marks a DTO field to be excluded from serialization by default.
 *
 * Usage:
 * ```php
 * class UserDto {
 *     public string $email;
 *
 *     #[ExcludeField]
 *     public ?string $password = null;
 * }
 * ```
 *
 * Fields with this attribute will be excluded from toArray() unless
 * explicitly requested via includeFields parameter.
 */
#[Attribute(Attribute::TARGET_PROPERTY)]
final class ExcludeField
{
    public function __construct(
        /** @var bool Whether the field is excluded by default */
        public readonly bool $defaultExcluded = true,
    ) {
    }
}
