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

use Symfony\Component\Security\Acl\Exception\NoAceFoundException;

/**
 * This interface represents an access control list (ACL) for a domain object.
 * Each domain object can have exactly one associated ACL.
 *
 * An ACL contains all access control entries (ACE) for a given domain object.
 * In order to avoid needing references to the domain object itself, implementations
 * use ObjectIdentity implementations as an additional level of indirection.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 *
 * @method array __serialize()              returns all the necessary state of the object for serialization purposes
 * @method void  __unserialize(array $data) restores the object state from an array given by {@see __serialize}
 */
interface AclInterface extends \Serializable
{
    /**
     * Returns all class-based ACEs associated with this ACL.
     *
     * @return array<int, EntryInterface>
     */
    public function getClassAces(): array;

    /**
     * Returns all class-field-based ACEs associated with this ACL.
     *
     * @return array<int, EntryInterface>
     */
    public function getClassFieldAces(string $field): array;

    /**
     * Returns all object-based ACEs associated with this ACL.
     *
     * @return array<int, EntryInterface>
     */
    public function getObjectAces(): array;

    /**
     * Returns all object-field-based ACEs associated with this ACL.
     *
     * @return array<int, EntryInterface>
     */
    public function getObjectFieldAces(string $field): array;

    /**
     * Returns the object identity associated with this ACL.
     */
    public function getObjectIdentity(): ObjectIdentityInterface;

    /**
     * Returns the parent ACL, or null if there is none.
     */
    public function getParentAcl(): self|int|null;

    /**
     * Whether this ACL is inheriting ACEs from a parent ACL.
     */
    public function isEntriesInheriting(): bool;

    /**
     * Determines whether field access is granted.
     *
     * @param int[]                       $masks
     * @param SecurityIdentityInterface[] $securityIdentities
     */
    public function isFieldGranted(string $field, array $masks, array $securityIdentities, bool $administrativeMode = false): bool;

    /**
     * Determines whether access is granted.
     *
     * @param int[]                       $masks
     * @param SecurityIdentityInterface[] $securityIdentities
     *
     * @throws NoAceFoundException when no ACE was applicable for this request
     */
    public function isGranted(array $masks, array $securityIdentities, bool $administrativeMode = false): bool;

    /**
     * Whether the ACL has loaded ACEs for all of the passed security identities.
     */
    public function isSidLoaded(SecurityIdentityInterface ...$securityIdentities): bool;
}
