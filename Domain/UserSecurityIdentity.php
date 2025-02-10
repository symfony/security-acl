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

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Util\ClassUtils;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A SecurityIdentity implementation used for actual users.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
final class UserSecurityIdentity implements SecurityIdentityInterface
{
    /**
     * @param string $username the username representation
     * @param string $class    the user's fully qualified class name
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(
        private readonly string $username,
        private readonly string $class,
    ) {
        if ('' === $username) {
            throw new \InvalidArgumentException('$username must not be empty.');
        }
        if (empty($class)) {
            throw new \InvalidArgumentException('$class must not be empty.');
        }
    }

    /**
     * Creates a user security identity from a UserInterface.
     */
    public static function fromAccount(UserInterface $user): self
    {
        return new self($user->getUserIdentifier(), ClassUtils::getRealClass($user));
    }

    /**
     * Creates a user security identity from a TokenInterface.
     */
    public static function fromToken(TokenInterface $token): self
    {
        $user = $token->getUser();

        if ($user instanceof UserInterface) {
            return self::fromAccount($user);
        }

        return new self((string) $user, ClassUtils::getRealClass($token));
    }

    /**
     * Returns the username.
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Returns the user's class name.
     */
    public function getClass(): string
    {
        return $this->class;
    }

    /**
     * {@inheritdoc}
     */
    public function equals(SecurityIdentityInterface $sid): bool
    {
        if (!$sid instanceof self) {
            return false;
        }

        return $this->username === $sid->getUsername()
               && $this->class === $sid->getClass();
    }

    /**
     * A textual representation of this security identity.
     *
     * This is not used for equality comparison, but only for debugging.
     */
    public function __toString(): string
    {
        return sprintf('UserSecurityIdentity(%s, %s)', $this->username, $this->class);
    }
}
