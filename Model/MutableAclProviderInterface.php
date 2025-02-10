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

use Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException;

/**
 * Provides support for creating and storing ACL instances.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface MutableAclProviderInterface extends AclProviderInterface
{
    /**
     * {@inheritdoc}
     */
    public function findAcl(ObjectIdentityInterface $oid, array $sids = []): AclInterface;

    /**
     * {@inheritdoc}
     *
     * @return \SplObjectStorage<ObjectIdentityInterface, MutableAclInterface> mapping the passed object identities to ACLs
     */
    public function findAcls(array $oids, array $sids = []): \SplObjectStorage;

    /**
     * Creates a new ACL for the given object identity.
     *
     * @throws AclAlreadyExistsException when there already is an ACL for the given
     *                                   object identity
     */
    public function createAcl(ObjectIdentityInterface $oid): MutableAclInterface;

    /**
     * Deletes the ACL for a given object identity.
     *
     * This will automatically trigger a delete for any child ACLs. If you don't
     * want child ACLs to be deleted, you will have to set their parent ACL to null.
     */
    public function deleteAcl(ObjectIdentityInterface $oid): void;

    /**
     * Persists any changes which were made to the ACL, or any associated
     * access control entries.
     *
     * Changes to parent ACLs are not persisted.
     */
    public function updateAcl(MutableAclInterface $acl): void;
}
