<?php

namespace Symfony\Component\Security\Acl\Tests\Fixtures;

use Symfony\Component\Security\Core\User\UserInterface;

final class Account implements UserInterface
{
    /** @var string */
    private $identifier;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    public function getUsername(): string
    {
        return $this->getUserIdentifier();
    }

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function getPassword(): ?string
    {
        return null;
    }

    public function getSalt(): ?string
    {
        return null;
    }

    public function eraseCredentials(): void
    {
    }
}
