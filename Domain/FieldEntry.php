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
use Symfony\Component\Security\Acl\Model\FieldEntryInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

/**
 * Field-aware ACE implementation which is auditable.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class FieldEntry extends Entry implements FieldEntryInterface
{
    public function __construct(
        ?int $id,
        AclInterface $acl,
        private readonly string $field,
        SecurityIdentityInterface $sid,
        string $strategy,
        int $mask,
        bool $granting,
        bool $auditFailure,
        bool $auditSuccess,
    ) {
        parent::__construct($id, $acl, $sid, $strategy, $mask, $granting, $auditFailure, $auditSuccess);
    }

    /**
     * {@inheritdoc}
     */
    public function getField(): string
    {
        return $this->field;
    }

    /**
     * {@inheritdoc}
     */
    public function __serialize(): array
    {
        return [$this->field, parent::__serialize()];
    }

    /**
     * {@inheritdoc}
     */
    public function __unserialize(array $data): void
    {
        [$this->field, $parentData] = $data;
        $parentData = \is_array($parentData) ? $parentData : unserialize($parentData);
        parent::__unserialize($parentData);
    }
}
