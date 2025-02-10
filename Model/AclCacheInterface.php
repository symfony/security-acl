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
 * AclCache Interface.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface AclCacheInterface
{
    /**
     * Removes an ACL from the cache.
     *
     * @param string $aclId a serialized primary key
     */
    public function evictFromCacheById(string $aclId): void;

    /**
     * Removes an ACL from the cache.
     *
     * The ACL which is returned, must reference the passed object identity.
     */
    public function evictFromCacheByIdentity(ObjectIdentityInterface $oid): void;

    /**
     * Retrieves an ACL for the given object identity primary key from the cache.
     */
    public function getFromCacheById(int $aclId): ?AclInterface;

    /**
     * Retrieves an ACL for the given object identity from the cache.
     */
    public function getFromCacheByIdentity(ObjectIdentityInterface $oid): ?AclInterface;

    /**
     * Stores a new ACL in the cache.
     */
    public function putInCache(AclInterface $acl): void;

    /**
     * Removes all ACLs from the cache.
     */
    public function clearCache(): void;
}
