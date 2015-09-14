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

use Symfony\Component\Security\Acl\Model\AclEntryInterface;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\EntryInterface;

/**
 * AclEntry
 *
 * @author Evgeniy Sokolov <ewgraf@gmail.com>
 */
class AclEntry implements AclEntryInterface
{
    private $acl;
    private $entry;

    public function __construct(AclInterface $acl, EntryInterface $entry)
    {
        $this->acl = $acl;
        $this->entry = $entry;
    }

    /**
     * @return AclInterface
     */
    public function getAcl()
    {
        return $this->acl;
    }

    /**
     * @return EntryInterface
     */
    public function getEntry()
    {
        return $this->entry;
    }
}
