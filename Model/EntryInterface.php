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

/**
 * This class represents an individual entry in the ACL list.
 *
 * Instances MUST be immutable, as they are returned by the ACL and should not
 * allow client modification.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 *
 * @method array __serialize()              returns all the necessary state of the object for serialization purposes
 * @method void  __unserialize(array $data) restores the object state from an array given by {@see __serialize}
 */
interface EntryInterface extends \Serializable
{
    /**
     * The ACL this ACE is associated with.
     */
    public function getAcl(): ?AclInterface;

    /**
     * The primary key of this ACE.
     */
    public function getId(): ?int;

    /**
     * The permission mask of this ACE.
     */
    public function getMask(): int;

    /**
     * The security identity associated with this ACE.
     */
    public function getSecurityIdentity(): SecurityIdentityInterface;

    /**
     * The strategy for comparing masks.
     */
    public function getStrategy(): string;

    /**
     * Returns whether this ACE is granting, or denying.
     */
    public function isGranting(): bool;
}
