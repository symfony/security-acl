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

use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

/**
 * Auditable ACE implementation.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class Entry implements AuditableEntryInterface
{
    public function __construct(
        private ?int $id,
        private readonly AclInterface $acl,
        private readonly SecurityIdentityInterface $securityIdentity,
        private string $strategy,
        private int $mask,
        private bool $granting,
        private bool $auditFailure,
        private bool $auditSuccess,
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function getAcl(): ?AclInterface
    {
        return $this->acl ?? null;
    }

    /**
     * {@inheritdoc}
     */
    public function getMask(): int
    {
        return $this->mask;
    }

    /**
     * {@inheritdoc}
     */
    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * {@inheritdoc}
     */
    public function getSecurityIdentity(): SecurityIdentityInterface
    {
        return $this->securityIdentity;
    }

    /**
     * {@inheritdoc}
     */
    public function getStrategy(): string
    {
        return $this->strategy;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuditFailure(): bool
    {
        return $this->auditFailure;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuditSuccess(): bool
    {
        return $this->auditSuccess;
    }

    /**
     * {@inheritdoc}
     */
    public function isGranting(): bool
    {
        return $this->granting;
    }

    /**
     * Turns on/off auditing on permissions denials.
     *
     * Do never call this method directly. Use the respective methods on the
     * AclInterface instead.
     */
    public function setAuditFailure(bool $boolean): void
    {
        $this->auditFailure = $boolean;
    }

    /**
     * Turns on/off auditing on permission grants.
     *
     * Do never call this method directly. Use the respective methods on the
     * AclInterface instead.
     */
    public function setAuditSuccess(bool $boolean): void
    {
        $this->auditSuccess = $boolean;
    }

    /**
     * Sets the permission mask.
     *
     * Do never call this method directly. Use the respective methods on the
     * AclInterface instead.
     */
    public function setMask(int $mask): void
    {
        $this->mask = $mask;
    }

    /**
     * Sets the mask comparison strategy.
     *
     * Do never call this method directly. Use the respective methods on the
     * AclInterface instead.
     */
    public function setStrategy(string $strategy): void
    {
        $this->strategy = $strategy;
    }

    public function __serialize(): array
    {
        return [
            $this->mask,
            $this->id,
            $this->securityIdentity,
            $this->strategy,
            $this->auditFailure,
            $this->auditSuccess,
            $this->granting,
        ];
    }

    public function __unserialize(array $data): void
    {
        [$this->mask,
            $this->id,
            $this->securityIdentity,
            $this->strategy,
            $this->auditFailure,
            $this->auditSuccess,
            $this->granting,
        ] = $data;
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
}
