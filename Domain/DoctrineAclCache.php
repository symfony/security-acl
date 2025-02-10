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

namespace Symfony\Component\Security\Acl\Domain;

use Doctrine\Common\Cache\Cache;
use Doctrine\Common\Cache\CacheProvider;
use Symfony\Component\Security\Acl\Model\AclCacheInterface;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;

/**
 * This class is a wrapper around the actual cache implementation.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class DoctrineAclCache implements AclCacheInterface
{
    use AclCacheTrait;

    public const PREFIX = 'sf2_acl_';

    /**
     * @throws \InvalidArgumentException
     */
    public function __construct(
        private Cache $cache,
        PermissionGrantingStrategyInterface $permissionGrantingStrategy,
        string $prefix = self::PREFIX,
    ) {
        if ('' === $prefix) {
            throw new \InvalidArgumentException('$prefix cannot be empty.');
        }

        $this->permissionGrantingStrategy = $permissionGrantingStrategy;
        $this->prefix = $prefix;
    }

    /**
     * {@inheritdoc}
     */
    public function clearCache(): void
    {
        if ($this->cache instanceof CacheProvider) {
            $this->cache->deleteAll();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function evictFromCacheById(string $aclId): void
    {
        $lookupKey = $this->getAliasKeyForIdentity($aclId);
        if (!$this->cache->contains($lookupKey)) {
            return;
        }

        $key = $this->cache->fetch($lookupKey);
        if ($this->cache->contains($key)) {
            $this->cache->delete($key);
        }

        $this->cache->delete($lookupKey);
    }

    /**
     * {@inheritdoc}
     */
    public function evictFromCacheByIdentity(ObjectIdentityInterface $oid): void
    {
        $key = $this->getDataKeyByIdentity($oid);
        if (!$this->cache->contains($key)) {
            return;
        }

        $this->cache->delete($key);
    }

    /**
     * {@inheritdoc}
     */
    public function getFromCacheById(int $aclId): ?AclInterface
    {
        $lookupKey = $this->getAliasKeyForIdentity((string)$aclId);
        if (!$this->cache->contains($lookupKey)) {
            return null;
        }

        $key = $this->cache->fetch($lookupKey);
        if (!$this->cache->contains($key)) {
            $this->cache->delete($lookupKey);

            return null;
        }

        return $this->unserializeAcl($this->cache->fetch($key));
    }

    /**
     * {@inheritdoc}
     */
    public function getFromCacheByIdentity(ObjectIdentityInterface $oid): ?AclInterface
    {
        $key = $this->getDataKeyByIdentity($oid);
        if (!$this->cache->contains($key)) {
            return null;
        }

        return $this->unserializeAcl($this->cache->fetch($key));
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
        $this->cache->save($key, serialize($acl));
        $this->cache->save($this->getAliasKeyForIdentity((string)$acl->getId()), $key);
    }
}
