<?php

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
 *
 * @template T of AclInterface
 */
class NotAllAclsFoundException extends AclNotFoundException
{
    private $partialResult;

    /**
     * @param \SplObjectStorage<ObjectIdentityInterface, T> $result
     */
    public function setPartialResult(\SplObjectStorage $result)
    {
        $this->partialResult = $result;
    }

    /**
     * Returns the partial result.
     *
     * @return \SplObjectStorage<ObjectIdentityInterface, T>
     */
    public function getPartialResult()
    {
        return $this->partialResult;
    }
}
