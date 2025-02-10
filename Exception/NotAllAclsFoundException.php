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

namespace Symfony\Component\Security\Acl\Exception;

use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;

/**
 * This exception is thrown when you have requested ACLs for multiple object
 * identities, but the AclProvider implementation failed to find ACLs for all
 * identities.
 *
 * This exception contains the partial result.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class NotAllAclsFoundException extends AclNotFoundException
{
    /**
     * @var \SplObjectStorage<ObjectIdentityInterface,AclInterface>
     */
    private \SplObjectStorage $partialResult;

    /**
     * @param \SplObjectStorage<ObjectIdentityInterface,AclInterface> $result
     */
    public function setPartialResult(\SplObjectStorage $result): void
    {
        $this->partialResult = $result;
    }

    /**
     * Returns the partial result.
     *
     * @return \SplObjectStorage<ObjectIdentityInterface,AclInterface>
     */
    public function getPartialResult(): \SplObjectStorage
    {
        return $this->partialResult;
    }
}
