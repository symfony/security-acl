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
 * This is the interface that must be implemented by permission maps.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface PermissionMapInterface
{
    /**
     * Returns an array of bitmasks.
     *
     * The security identity must have been granted access to at least one of
     * these bitmasks.
     *
     * @return int[]|null may return null if permission/object combination is not supported
     */
    public function getMasks(string $permission, $object): ?array;

    /**
     * Whether this map contains the given permission.
     */
    public function contains(string $permission): bool;
}
