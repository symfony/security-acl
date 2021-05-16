<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Acl\Domain;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Security\Acl\Model\AclCacheInterface;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;

/**
 * This class is a wrapper around a PSR-6 cache implementation.
 *
 * @author Michael Babker <michael.babker@gmail.com>
 */
class PsrAclCache implements AclCacheInterface
{
    use AclCacheTrait;

    public const PREFIX = 'sf_acl_';

    private $cache;

    /**
     * @throws \InvalidArgumentException When $prefix is empty
     */
    public function __construct(CacheItemPoolInterface $cache, PermissionGrantingStrategyInterface $permissionGrantingStrategy, string $prefix = self::PREFIX)
    {
        if (0 === \strlen($prefix)) {
            throw new \InvalidArgumentException('$prefix cannot be empty.');
        }

        $this->cache = $cache;
        $this->permissionGrantingStrategy = $permissionGrantingStrategy;
        $this->prefix = $prefix;
    }

    /**
     * {@inheritdoc}
     */
    public function clearCache(): void
    {
        $this->cache->clear();
    }

    /**
     * {@inheritdoc}
     */
    public function evictFromCacheById($aclId): void
    {
        $lookupKey = $this->getAliasKeyForIdentity($aclId);
        $cacheItem = $this->cache->getItem($lookupKey);
        if (!$cacheItem->isHit()) {
            return;
        }

        $this->cache->deleteItems([$cacheItem->get(), $lookupKey]);
    }

    /**
     * {@inheritdoc}
     */
    public function evictFromCacheByIdentity(ObjectIdentityInterface $oid): void
    {
        $this->cache->deleteItem($this->getDataKeyByIdentity($oid));
    }

    /**
     * {@inheritdoc}
     */
    public function getFromCacheById($aclId): ?AclInterface
    {
        $lookupKey = $this->getAliasKeyForIdentity($aclId);
        $lookupKeyItem = $this->cache->getItem($lookupKey);
        if (!$lookupKeyItem->isHit()) {
            return null;
        }

        $key = $lookupKeyItem->get();
        $keyItem = $this->cache->getItem($key);
        if (!$keyItem->isHit()) {
            $this->cache->deleteItem($lookupKey);

            return null;
        }

        return $this->unserializeAcl($keyItem->get());
    }

    /**
     * {@inheritdoc}
     */
    public function getFromCacheByIdentity(ObjectIdentityInterface $oid): ?AclInterface
    {
        $key = $this->getDataKeyByIdentity($oid);
        $cacheItem = $this->cache->getItem($key);
        if (!$cacheItem->isHit()) {
            return null;
        }

        return $this->unserializeAcl($cacheItem->get());
    }

    /**
     * {@inheritdoc}
     */
    public function putInCache(AclInterface $acl): void
    {
        if (null === $acl->getId()) {
            throw new \InvalidArgumentException('Transient ACLs cannot be cached.');
        }

        if (null !== $parentAcl = $acl->getParentAcl()) {
            $this->putInCache($parentAcl);
        }

        $key = $this->getDataKeyByIdentity($acl->getObjectIdentity());
        $objectIdentityItem = $this->cache->getItem($key);
        $objectIdentityItem->set(serialize($acl));

        $this->cache->saveDeferred($objectIdentityItem);

        $aliasKey = $this->getAliasKeyForIdentity($acl->getId());
        $aliasItem = $this->cache->getItem($aliasKey);
        $aliasItem->set($key);

        $this->cache->saveDeferred($aliasItem);

        $this->cache->commit();
    }
}
