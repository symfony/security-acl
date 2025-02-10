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

namespace Symfony\Component\Security\Acl\Model;

/**
 * Interface used by permission granting implementations.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface PermissionGrantingStrategyInterface
{
    /**
     * Determines whether access to a domain object is to be granted.
     *
     * @param int[]                       $masks
     * @param SecurityIdentityInterface[] $sids
     */
    public function isGranted(AclInterface $acl, array $masks, array $sids, bool $administrativeMode = false): bool;

    /**
     * Determines whether access to a domain object's field is to be granted.
     *
     * @param int[]                       $masks
     * @param SecurityIdentityInterface[] $sids
     */
    public function isFieldGranted(AclInterface $acl, string $field, array $masks, array $sids, bool $administrativeMode = false): bool;
}
