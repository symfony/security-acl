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
    private $field;

    public function __construct(?int $id, AclInterface $acl, string $field, SecurityIdentityInterface $sid, string $strategy, int $mask, bool $granting, bool $auditFailure, $auditSuccess)
    {
        parent::__construct($id, $acl, $sid, $strategy, $mask, $granting, $auditFailure, $auditSuccess);

        $this->field = $field;
    }

    /**
     * {@inheritdoc}
     */
    public function getField()
    {
        return $this->field;
    }

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize([
            $this->field,
            parent::serialize(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        [$this->field, $parentStr] = unserialize($serialized);
        if (!\is_string($parentStr)) {
            throw new \BadMethodCallException('Cannot serialize '.__CLASS__);
        }
        parent::unserialize($parentStr);
    }
}
