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
 * Represents the identity of an individual domain object instance.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface ObjectIdentityInterface
{
    /**
     * We specifically require this method so we can check for object equality
     * explicitly, and do not have to rely on referencial equality instead.
     *
     * Though in most cases, both checks should result in the same outcome.
     *
     * Referential Equality: $object1 === $object2
     * Example for Object Equality: $object1->getId() === $object2->getId()
     */
    public function equals(self $identity): bool;

    /**
     * Obtains a unique identifier for this object. The identifier must not be
     * re-used for other objects with the same type.
     *
     * @return string cannot return null
     */
    public function getIdentifier(): string;

    /**
     * Returns a type for the domain object. Typically, this is the PHP class name.
     *
     * @return string cannot return null
     */
    public function getType(): string;
}
