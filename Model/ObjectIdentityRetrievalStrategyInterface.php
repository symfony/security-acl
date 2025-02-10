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
 * Retrieves the object identity for a given domain object.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface ObjectIdentityRetrievalStrategyInterface
{
    /**
     * Retrieves the object identity from a domain object.
     */
    public function getObjectIdentity(object $domainObject): ?ObjectIdentityInterface;
}
