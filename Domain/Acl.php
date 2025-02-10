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

use Doctrine\Persistence\NotifyPropertyChanged;
use Doctrine\Persistence\PropertyChangedListener;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\AuditableAclInterface;
use Symfony\Component\Security\Acl\Model\EntryInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\PermissionGrantingStrategyInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

/**
 * An ACL implementation.
 *
 * Each object identity has exactly one associated ACL. Each ACL can have four
 * different types of ACEs (class ACEs, object ACEs, class field ACEs, object field
 * ACEs).
 *
 * You should not iterate over the ACEs yourself, but instead use isGranted(),
 * or isFieldGranted(). These will utilize an implementation of PermissionGrantingStrategy
 * internally.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class Acl implements AuditableAclInterface, NotifyPropertyChanged
{
    private AclInterface|int|null $parentAcl = null;

    /**
     * @var Entry[]
     */
    private array $classAces = [];

    /**
     * @var array<string,Entry[]>
     */
    private array $classFieldAces = [];

    /**
     * @var Entry[]
     */
    private array $objectAces = [];

    /**
     * @var array<string,Entry[]>
     */
    private array $objectFieldAces = [];

    /**
     * @var PropertyChangedListener[]
     */
    private array $listeners = [];

    /**
     * @param SecurityIdentityInterface[] $loadedSids
     */
    public function __construct(
        private int $id,
        private ObjectIdentityInterface $objectIdentity,
        private PermissionGrantingStrategyInterface $permissionGrantingStrategy,
        private array $loadedSids,
        private bool $entriesInheriting,
    ) {
    }

    /**
     * Adds a property changed listener.
     */
    public function addPropertyChangedListener(PropertyChangedListener $listener): void
    {
        $this->listeners[] = $listener;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteClassAce(int $index): void
    {
        $this->deleteAce('classAces', $index);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteClassFieldAce(int $index, string $field): void
    {
        $this->deleteFieldAce('classFieldAces', $index, $field);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteObjectAce(int $index): void
    {
        $this->deleteAce('objectAces', $index);
    }

    /**
     * {@inheritdoc}
     */
    public function deleteObjectFieldAce(int $index, string $field): void
    {
        $this->deleteFieldAce('objectFieldAces', $index, $field);
    }

    /**
     * {@inheritdoc}
     */
    public function getClassAces(): array
    {
        return $this->classAces;
    }

    /**
     * {@inheritdoc}
     */
    public function getClassFieldAces(string $field): array
    {
        return $this->classFieldAces[$field] ?? [];
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectAces(): array
    {
        return $this->objectAces;
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectFieldAces(string $field): array
    {
        return $this->objectFieldAces[$field] ?? [];
    }

    /**
     * {@inheritdoc}
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectIdentity(): ObjectIdentityInterface
    {
        return $this->objectIdentity;
    }

    /**
     * {@inheritdoc}
     */
    public function getParentAcl(): AclInterface|int|null
    {
        return $this->parentAcl;
    }

    /**
     * {@inheritdoc}
     */
    public function insertClassAce(SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null): void
    {
        $this->insertAce('classAces', $index, $mask, $sid, $granting, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function insertClassFieldAce(string $field, SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null): void
    {
        $this->insertFieldAce('classFieldAces', $index, $field, $mask, $sid, $granting, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function insertObjectAce(SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null): void
    {
        $this->insertAce('objectAces', $index, $mask, $sid, $granting, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function insertObjectFieldAce(string $field, SecurityIdentityInterface $sid, int $mask, int $index = 0, bool $granting = true, ?string $strategy = null): void
    {
        $this->insertFieldAce('objectFieldAces', $index, $field, $mask, $sid, $granting, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function isEntriesInheriting(): bool
    {
        return $this->entriesInheriting;
    }

    /**
     * {@inheritdoc}
     */
    public function isFieldGranted(string $field, array $masks, array $securityIdentities, bool $administrativeMode = false): bool
    {
        return $this->permissionGrantingStrategy->isFieldGranted($this, $field, $masks, $securityIdentities, $administrativeMode);
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted(array $masks, array $securityIdentities, bool $administrativeMode = false): bool
    {
        return $this->permissionGrantingStrategy->isGranted($this, $masks, $securityIdentities, $administrativeMode);
    }

    /**
     * {@inheritdoc}
     */
    public function isSidLoaded(SecurityIdentityInterface ...$securityIdentities): bool
    {
        if (!$this->loadedSids) {
            return true;
        }

        foreach ($securityIdentities as $sid) {
            foreach ($this->loadedSids as $loadedSid) {
                if ($loadedSid->equals($sid)) {
                    continue 2;
                }
            }

            return false;
        }

        return true;
    }

    public function __serialize(): array
    {
        return [
            $this->parentAcl?->getId(),
            $this->objectIdentity,
            $this->classAces,
            $this->classFieldAces,
            $this->objectAces,
            $this->objectFieldAces,
            $this->id,
            $this->loadedSids,
            $this->entriesInheriting,
        ];
    }

    public function __unserialize(array $data): void
    {
        [$this->parentAcl,
            $this->objectIdentity,
            $this->classAces,
            $this->classFieldAces,
            $this->objectAces,
            $this->objectFieldAces,
            $this->id,
            $this->loadedSids,
            $this->entriesInheriting,
        ] = $data;

        $this->listeners = [];
    }

    /**
     * @internal
     *
     * @final
     *
     * @return string
     */
    public function serialize()
    {
        return serialize($this->__serialize());
    }

    /**
     * @internal
     *
     * @final
     *
     * @param string $data
     */
    public function unserialize($data)
    {
        $this->__unserialize(unserialize($data));
    }

    /**
     * {@inheritdoc}
     */
    public function setEntriesInheriting(bool $boolean): void
    {
        if ($this->entriesInheriting !== $boolean) {
            $this->onPropertyChanged('entriesInheriting', $this->entriesInheriting, $boolean);
            $this->entriesInheriting = $boolean;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function setParentAcl(?AclInterface $acl = null): void
    {
        if (null !== $acl && null === $acl->getId()) {
            throw new \InvalidArgumentException('$acl must have an ID.');
        }

        if ($this->parentAcl !== $acl) {
            $this->onPropertyChanged('parentAcl', $this->parentAcl, $acl);
            $this->parentAcl = $acl;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function updateClassAce(int $index, int $mask, ?string $strategy = null): void
    {
        $this->updateAce('classAces', $index, $mask, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function updateClassFieldAce(int $index, string $field, int $mask, ?string $strategy = null): void
    {
        $this->updateFieldAce('classFieldAces', $index, $field, $mask, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectAce(int $index, int $mask, ?string $strategy = null): void
    {
        $this->updateAce('objectAces', $index, $mask, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectFieldAce(int $index, string $field, int $mask, ?string $strategy = null): void
    {
        $this->updateFieldAce('objectFieldAces', $index, $field, $mask, $strategy);
    }

    /**
     * {@inheritdoc}
     */
    public function updateClassAuditing(int $index, bool $auditSuccess, bool $auditFailure): void
    {
        $this->updateAuditing($this->classAces, $index, $auditSuccess, $auditFailure);
    }

    /**
     * {@inheritdoc}
     */
    public function updateClassFieldAuditing(int $index, string $field, bool $auditSuccess, bool $auditFailure): void
    {
        if (!isset($this->classFieldAces[$field])) {
            throw new \InvalidArgumentException(sprintf('There are no ACEs for field "%s".', $field));
        }

        $this->updateAuditing($this->classFieldAces[$field], $index, $auditSuccess, $auditFailure);
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectAuditing(int $index, bool $auditSuccess, bool $auditFailure): void
    {
        $this->updateAuditing($this->objectAces, $index, $auditSuccess, $auditFailure);
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectFieldAuditing(int $index, string $field, bool $auditSuccess, bool $auditFailure): void
    {
        if (!isset($this->objectFieldAces[$field])) {
            throw new \InvalidArgumentException(sprintf('There are no ACEs for field "%s".', $field));
        }

        $this->updateAuditing($this->objectFieldAces[$field], $index, $auditSuccess, $auditFailure);
    }

    /**
     * Deletes an ACE.
     *
     * @throws \OutOfBoundsException
     */
    private function deleteAce(string $property, int $index): void
    {
        $aces = &$this->$property;
        if (!isset($aces[$index])) {
            throw new \OutOfBoundsException(sprintf('The index "%d" does not exist.', $index));
        }

        $oldValue = $this->$property;
        unset($aces[$index]);
        $this->$property = array_values($this->$property);
        $this->onPropertyChanged($property, $oldValue, $this->$property);

        for ($i = $index, $c = \count($this->$property); $i < $c; ++$i) {
            $this->onEntryPropertyChanged($aces[$i], 'aceOrder', $i + 1, $i);
        }
    }

    /**
     * Deletes a field-based ACE.
     *
     * @throws \OutOfBoundsException
     */
    private function deleteFieldAce(string $property, int $index, string $field): void
    {
        $aces = &$this->$property;
        if (!isset($aces[$field][$index])) {
            throw new \OutOfBoundsException(sprintf('The index "%d" does not exist.', $index));
        }

        $oldValue = $this->$property;
        unset($aces[$field][$index]);
        $aces[$field] = array_values($aces[$field]);
        $this->onPropertyChanged($property, $oldValue, $this->$property);

        for ($i = $index, $c = \count($aces[$field]); $i < $c; ++$i) {
            $this->onEntryPropertyChanged($aces[$field][$i], 'aceOrder', $i + 1, $i);
        }
    }

    /**
     * Inserts an ACE.
     *
     * @throws \OutOfBoundsException
     * @throws \InvalidArgumentException
     */
    private function insertAce(string $property, int $index, int $mask, SecurityIdentityInterface $sid, bool $granting, ?string $strategy = null): void
    {
        if ($index < 0 || $index > \count($this->$property)) {
            throw new \OutOfBoundsException(sprintf('The index must be in the interval [0, %d].', \count($this->$property)));
        }

        if (null === $strategy) {
            if (true === $granting) {
                $strategy = PermissionGrantingStrategy::ALL;
            } else {
                $strategy = PermissionGrantingStrategy::ANY;
            }
        }

        $aces = &$this->$property;
        $oldValue = $this->$property;
        if (isset($aces[$index])) {
            $this->$property = array_merge(
                \array_slice($this->$property, 0, $index),
                [true],
                \array_slice($this->$property, $index)
            );

            for ($i = $index, $c = \count($this->$property) - 1; $i < $c; ++$i) {
                $this->onEntryPropertyChanged($aces[$i + 1], 'aceOrder', $i, $i + 1);
            }
        }

        $aces[$index] = new Entry(null, $this, $sid, $strategy, $mask, $granting, false, false);
        $this->onPropertyChanged($property, $oldValue, $this->$property);
    }

    /**
     * Inserts a field-based ACE.
     *
     * @throws \InvalidArgumentException
     * @throws \OutOfBoundsException
     */
    private function insertFieldAce(string $property, int $index, string $field, int $mask, SecurityIdentityInterface $sid, bool $granting, ?string $strategy = null): void
    {
        if ('' === $field) {
            throw new \InvalidArgumentException('$field cannot be empty.');
        }

        if (null === $strategy) {
            if (true === $granting) {
                $strategy = PermissionGrantingStrategy::ALL;
            } else {
                $strategy = PermissionGrantingStrategy::ANY;
            }
        }

        $aces = &$this->$property;
        if (!isset($aces[$field])) {
            $aces[$field] = [];
        }

        if ($index < 0 || $index > \count($aces[$field])) {
            throw new \OutOfBoundsException(sprintf('The index must be in the interval [0, %d].', \count($this->$property)));
        }

        $oldValue = $aces;
        if (isset($aces[$field][$index])) {
            $aces[$field] = array_merge(
                \array_slice($aces[$field], 0, $index),
                [true],
                \array_slice($aces[$field], $index)
            );

            for ($i = $index, $c = \count($aces[$field]) - 1; $i < $c; ++$i) {
                $this->onEntryPropertyChanged($aces[$field][$i + 1], 'aceOrder', $i, $i + 1);
            }
        }

        $aces[$field][$index] = new FieldEntry(null, $this, $field, $sid, $strategy, $mask, $granting, false, false);
        $this->onPropertyChanged($property, $oldValue, $this->$property);
    }

    /**
     * Updates an ACE.
     *
     * @throws \OutOfBoundsException
     */
    private function updateAce(string $property, int $index, int $mask, ?string $strategy = null): void
    {
        $aces = &$this->$property;
        if (!isset($aces[$index])) {
            throw new \OutOfBoundsException(sprintf('The index "%d" does not exist.', $index));
        }

        $ace = $aces[$index];
        if ($mask !== $oldMask = $ace->getMask()) {
            $this->onEntryPropertyChanged($ace, 'mask', $oldMask, $mask);
            $ace->setMask($mask);
        }
        if (null !== $strategy && $strategy !== $oldStrategy = $ace->getStrategy()) {
            $this->onEntryPropertyChanged($ace, 'strategy', $oldStrategy, $strategy);
            $ace->setStrategy($strategy);
        }
    }

    /**
     * Updates auditing for an ACE.
     *
     * @param array<int,Entry> &$aces
     *
     * @throws \OutOfBoundsException
     */
    private function updateAuditing(array &$aces, int $index, bool $auditSuccess, bool $auditFailure): void
    {
        if (!isset($aces[$index])) {
            throw new \OutOfBoundsException(sprintf('The index "%d" does not exist.', $index));
        }

        if ($auditSuccess !== $aces[$index]->isAuditSuccess()) {
            $this->onEntryPropertyChanged($aces[$index], 'auditSuccess', !$auditSuccess, $auditSuccess);
            $aces[$index]->setAuditSuccess($auditSuccess);
        }

        if ($auditFailure !== $aces[$index]->isAuditFailure()) {
            $this->onEntryPropertyChanged($aces[$index], 'auditFailure', !$auditFailure, $auditFailure);
            $aces[$index]->setAuditFailure($auditFailure);
        }
    }

    /**
     * Updates a field-based ACE.
     *
     * @throws \InvalidArgumentException
     * @throws \OutOfBoundsException
     */
    private function updateFieldAce(string $property, int $index, string $field, int $mask, ?string $strategy = null): void
    {
        if ('' === $field) {
            throw new \InvalidArgumentException('$field cannot be empty.');
        }

        $aces = &$this->$property;
        if (!isset($aces[$field][$index])) {
            throw new \OutOfBoundsException(sprintf('The index "%d" does not exist.', $index));
        }

        $ace = $aces[$field][$index];
        if ($mask !== $oldMask = $ace->getMask()) {
            $this->onEntryPropertyChanged($ace, 'mask', $oldMask, $mask);
            $ace->setMask($mask);
        }
        if (null !== $strategy && $strategy !== $oldStrategy = $ace->getStrategy()) {
            $this->onEntryPropertyChanged($ace, 'strategy', $oldStrategy, $strategy);
            $ace->setStrategy($strategy);
        }
    }

    /**
     * Called when a property of the ACL changes.
     */
    private function onPropertyChanged(string $name, mixed $oldValue, mixed $newValue): void
    {
        foreach ($this->listeners as $listener) {
            $listener->propertyChanged($this, $name, $oldValue, $newValue);
        }
    }

    /**
     * Called when a property of an ACE associated with this ACL changes.
     */
    private function onEntryPropertyChanged(EntryInterface $entry, string $name, mixed $oldValue, mixed $newValue): void
    {
        foreach ($this->listeners as $listener) {
            $listener->propertyChanged($entry, $name, $oldValue, $newValue);
        }
    }
}
