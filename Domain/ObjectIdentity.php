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

use Symfony\Component\Security\Acl\Exception\InvalidDomainObjectException;
use Symfony\Component\Security\Acl\Model\DomainObjectInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Util\ClassUtils;

/**
 * ObjectIdentity implementation.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
final class ObjectIdentity implements ObjectIdentityInterface
{
    private readonly string $identifier;

    /**
     * @throws \InvalidArgumentException
     */
    public function __construct(
        string|int $identifier,
        private readonly string $type,
    ) {
        $this->identifier = (string) $identifier;

        if ('' === $this->identifier) {
            throw new \InvalidArgumentException('$identifier cannot be empty.');
        }
        if (empty($type)) {
            throw new \InvalidArgumentException('$type cannot be empty.');
        }
    }

    /**
     * Constructs an ObjectIdentity for the given domain object.
     *
     * @throws InvalidDomainObjectException
     */
    public static function fromDomainObject(object $domainObject): self
    {
        try {
            if ($domainObject instanceof DomainObjectInterface) {
                return new self($domainObject->getObjectIdentifier(), ClassUtils::getRealClass($domainObject));
            } elseif (method_exists($domainObject, 'getId')) {
                return new self((string) $domainObject->getId(), ClassUtils::getRealClass($domainObject));
            }
        } catch (\InvalidArgumentException $e) {
            throw new InvalidDomainObjectException($e->getMessage(), 0, $e);
        }

        throw new InvalidDomainObjectException('$domainObject must either implement the DomainObjectInterface, or have a method named "getId".');
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * {@inheritdoc}
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * {@inheritdoc}
     */
    public function equals(ObjectIdentityInterface $identity): bool
    {
        // comparing the identifier with === might lead to problems, so we
        // waive this restriction
        return $this->identifier == $identity->getIdentifier()
               && $this->type === $identity->getType();
    }

    /**
     * Returns a textual representation of this object identity.
     *
     * @return string
     */
    public function __toString()
    {
        return sprintf('ObjectIdentity(%s, %s)', $this->identifier, $this->type);
    }
}
