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

/**
 * This method can be implemented by domain objects which you want to store
 * ACLs for if they do not have a getId() method, or getId() does not return
 * a unique identifier.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface DomainObjectInterface
{
    /**
     * Returns a unique identifier for this domain object.
     */
    public function getObjectIdentifier(): string;
}
