<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Acl\Model;

use Symfony\Component\Security\Acl\Exception\AclNotFoundException;

/**
 * Provides a common interface for retrieving ACLs.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface AclProviderInterface
{
    /**
     * Retrieves all child object identities from the database.
     *
     * @return ObjectIdentityInterface[] returns an array of child 'ObjectIdentity's
     */
    public function findChildren(ObjectIdentityInterface $parentOid, bool $directChildrenOnly = false): array;

    /**
     * Returns the ACL that belongs to the given object identity.
     *
     * @param SecurityIdentityInterface[] $sids
     *
     * @throws AclNotFoundException when there is no ACL
     */
    public function findAcl(ObjectIdentityInterface $oid, array $sids = []): AclInterface;

    /**
     * Returns the ACLs that belong to the given object identities.
     *
     * @param ObjectIdentityInterface[]   $oids an array of ObjectIdentityInterface implementations
     * @param SecurityIdentityInterface[] $sids an array of SecurityIdentityInterface implementations
     *
     * @return \SplObjectStorage<ObjectIdentityInterface, AclInterface> mapping the passed object identities to ACLs
     *
     * @throws AclNotFoundException when we cannot find an ACL for all identities
     */
    public function findAcls(array $oids, array $sids = []): \SplObjectStorage;
}
