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
 * This interface adds mutators for the AclInterface.
 *
 * All changes to Access Control Entries must go through this interface. Access
 * Control Entries must never be modified directly.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface MutableAclInterface extends AclInterface
{
    /**
     * Deletes a class-based ACE.
     */
    public function deleteClassAce(int $index);

    /**
     * Deletes a class-field-based ACE.
     */
    public function deleteClassFieldAce(int $index, string $field);

    /**
     * Deletes an object-based ACE.
     */
    public function deleteObjectAce(int $index);

    /**
     * Deletes an object-field-based ACE.
     */
    public function deleteObjectFieldAce(int $index, string $field);

    /**
     * Returns the primary key of this ACL.
     *
     * @return int
     */
    public function getId();

    /**
     * Inserts a class-based ACE.
     */
    public function insertClassAce(SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null);

    /**
     * Inserts a class-field-based ACE.
     */
    public function insertClassFieldAce(string $field, SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null);

    /**
     * Inserts an object-based ACE.
     */
    public function insertObjectAce(SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null);

    /**
     * Inserts an object-field-based ACE.
     */
    public function insertObjectFieldAce(string $field, SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null);

    /**
     * Sets whether entries are inherited.
     */
    public function setEntriesInheriting(bool $boolean);

    /**
     * Sets the parent ACL.
     */
    public function setParentAcl(?AclInterface $acl = null);

    /**
     * Updates a class-based ACE.
     *
     * @param string|null $strategy if null the strategy should not be changed
     */
    public function updateClassAce(int $index, int $mask, ?string $strategy = null);

    /**
     * Updates a class-field-based ACE.
     *
     * @param string|null $strategy if null the strategy should not be changed
     */
    public function updateClassFieldAce(int $index, string $field, int $mask, ?string $strategy = null);

    /**
     * Updates an object-based ACE.
     *
     * @param string|null $strategy if null the strategy should not be changed
     */
    public function updateObjectAce(int $index, int $mask, ?string $strategy = null);

    /**
     * Updates an object-field-based ACE.
     *
     * @param string|null $strategy if null the strategy should not be changed
     */
    public function updateObjectFieldAce(int $index, string $field, int $mask, ?string $strategy = null);
}
