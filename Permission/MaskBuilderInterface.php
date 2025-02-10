<?php

declare(strict_types=1);

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Acl\Permission;

/**
 * This is the interface that must be implemented by mask builders.
 */
interface MaskBuilderInterface
{
    /**
     * Set the mask of this permission.
     *
     * @throws \InvalidArgumentException if $mask is not an integer
     */
    public function set(int $mask): self;

    /**
     * Returns the mask of this permission.
     */
    public function get(): int;

    /**
     * Adds a mask to the permission.
     *
     * @throws \InvalidArgumentException
     */
    public function add(int $mask): self;

    /**
     * Removes a mask from the permission.
     *
     * @throws \InvalidArgumentException
     */
    public function remove(int $mask): self;

    /**
     * Resets the PermissionBuilder.
     */
    public function reset(): self;

    /**
     * Returns the mask for the passed code.
     *
     * @throws \InvalidArgumentException
     */
    public function resolveMask(string|int $code): int;
}
