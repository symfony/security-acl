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
 * This class represents an entry and acl.
 *
 * Instances MUST be immutable, as they are returned by the ACL and should not
 * allow client modification.
 *
 * @author Evgeniy Sokolov <ewgraf@gmail.com>
 */
interface AclEntryInterface
{
    /**
     * Acl
     *
     * @return AclInterface
     */
    public function getAcl();

    /**
     * Entry
     *
     * @return EntryInterface
     */
    public function getEntry();
}
