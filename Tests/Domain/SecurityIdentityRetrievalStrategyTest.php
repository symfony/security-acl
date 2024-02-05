<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Acl\Tests\Domain;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\SecurityIdentityRetrievalStrategy;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Tests\Fixtures\Account;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class SecurityIdentityRetrievalStrategyTest extends TestCase
{
    /**
     * @dataProvider getSecurityIdentityRetrievalTests
     */
    public function testGetSecurityIdentities($user, array $roles, string $authenticationStatus, array $sids)
    {
        $token = class_exists(NullToken::class) ? new NullToken() : new AnonymousToken('', '');
        if ('anonymous' !== $authenticationStatus) {
            $class = '';
            if (\is_string($user)) {
                $class = 'MyCustomTokenImpl';
            }

            $token = $this->getMockBuilder(AbstractToken::class)
                ->setMockClassName($class)
                ->getMock();

            $token
                ->expects($this->once())
                ->method('getRoleNames')
                ->willReturn(['foo'])
            ;

            $token
                ->expects($this->once())
                ->method('getUser')
                ->willReturn($user)
            ;
        }

        $strategy = $this->getStrategy($roles, $authenticationStatus);
        $extractedSids = $strategy->getSecurityIdentities($token);

        foreach ($extractedSids as $index => $extractedSid) {
            if (!isset($sids[$index])) {
                $this->fail(sprintf('Expected SID at index %d, but there was none.', $index));
            }

            if (false === $sids[$index]->equals($extractedSid)) {
                $this->fail(sprintf('Index: %d, expected SID "%s", but got "%s".', $index, $sids[$index], (string) $extractedSid));
            }
        }
    }

    /**
     * @group legacy
     *
     * @dataProvider getDeprecatedSecurityIdentityRetrievalTests
     */
    public function testDeprecatedGetSecurityIdentities($user, array $roles, string $authenticationStatus, array $sids)
    {
        if (method_exists(AuthenticationTrustResolverInterface::class, 'isAuthenticated')) {
            $this->markTestSkipped();
        }

        if ('anonymous' === $authenticationStatus) {
            $token = $this->getMockBuilder(AnonymousToken::class)
                ->disableOriginalConstructor()
                ->getMock();
        } else {
            $class = '';
            if (\is_string($user)) {
                $class = 'MyCustomTokenImpl';
            }

            $token = $this->getMockBuilder(AbstractToken::class)
                ->setMockClassName($class)
                ->getMock();
        }

        $strategy = $this->getStrategy($roles, $authenticationStatus);

        $token
            ->expects($this->once())
            ->method('getRoleNames')
            ->willReturn(['foo'])
        ;

        if ('anonymous' === $authenticationStatus) {
            $token
                ->expects($this->never())
                ->method('getUser')
            ;
        } else {
            $token
                ->expects($this->once())
                ->method('getUser')
                ->willReturn($user)
            ;
        }

        $extractedSids = $strategy->getSecurityIdentities($token);

        foreach ($extractedSids as $index => $extractedSid) {
            if (!isset($sids[$index])) {
                $this->fail(sprintf('Expected SID at index %d, but there was none.', $index));
            }

            if (false === $sids[$index]->equals($extractedSid)) {
                $this->fail(sprintf('Index: %d, expected SID "%s", but got "%s".', $index, $sids[$index], (string) $extractedSid));
            }
        }
    }

    public function getSecurityIdentityRetrievalTests(): array
    {
        $anonymousRoles = [new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY')];
        if (\defined('\Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter::PUBLIC_ACCESS')) {
            $anonymousRoles[] = new RoleSecurityIdentity(AuthenticatedVoter::PUBLIC_ACCESS);
        }

        return [
            [new Account('johannes'), ['ROLE_USER', 'ROLE_SUPERADMIN'], 'fullFledged', array_merge([
                new UserSecurityIdentity('johannes', Account::class),
                new RoleSecurityIdentity('ROLE_USER'),
                new RoleSecurityIdentity('ROLE_SUPERADMIN'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_FULLY'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
            ], $anonymousRoles)],
            [new CustomUserImpl('johannes'), ['ROLE_FOO'], 'fullFledged', array_merge([
                new UserSecurityIdentity('johannes', CustomUserImpl::class),
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_FULLY'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
            ], $anonymousRoles)],
            [new Account('foo'), ['ROLE_FOO'], 'rememberMe', array_merge([
                new UserSecurityIdentity('foo', Account::class),
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
            ], $anonymousRoles)],
            ['guest', [], 'anonymous', $anonymousRoles],
        ];
    }

    public function getDeprecatedSecurityIdentityRetrievalTests()
    {
        $anonymousRoles = [new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY')];
        if (\defined('\Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter::PUBLIC_ACCESS')) {
            $anonymousRoles[] = new RoleSecurityIdentity(AuthenticatedVoter::PUBLIC_ACCESS);
        }

        return [
            ['johannes', ['ROLE_FOO'], 'fullFledged', array_merge([
                new UserSecurityIdentity('johannes', 'MyCustomTokenImpl'),
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_FULLY'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
            ], $anonymousRoles)],
            ['guest', ['ROLE_FOO'], 'anonymous', array_merge([
                new RoleSecurityIdentity('ROLE_FOO'),
            ], $anonymousRoles)],
        ];
    }

    private function getStrategy(array $roles, string $authenticationStatus): SecurityIdentityRetrievalStrategy
    {
        $roleHierarchy = new class($roles) implements RoleHierarchyInterface {
            private $roles;

            public function __construct(array $roles)
            {
                $this->roles = $roles;
            }

            public function getReachableRoleNames(array $roles): array
            {
                return $this->roles;
            }
        };

        $trustResolverMockBuild = $this->getMockBuilder(AuthenticationTrustResolverInterface::class);
        if (\defined('\Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter::PUBLIC_ACCESS')) {
            if (method_exists(AuthenticationTrustResolverInterface::class, 'isAuthenticated')) {
                $trustResolver = $trustResolverMockBuild->getMock();
            } else {
                $trustResolver = $trustResolverMockBuild
                    ->onlyMethods(['isAnonymous', 'isRememberMe', 'isFullFledged'])
                    ->addMethods(['isAuthenticated'])
                    ->getMock()
                ;
            }
            $trustResolver
                ->method('isAuthenticated')
                ->willReturn('anonymous' !== $authenticationStatus);
        } else {
            $trustResolver = $trustResolverMockBuild->getMock();
            $trustResolver
                ->method('isAnonymous')
                ->willReturn('anonymous' === $authenticationStatus);
        }

        if ('fullFledged' === $authenticationStatus) {
            $trustResolver
                ->expects($this->once())
                ->method('isFullFledged')
                ->willReturn(true)
            ;
            $trustResolver
                ->expects($this->never())
                ->method('isRememberMe')
            ;
        } elseif ('rememberMe' === $authenticationStatus) {
            $trustResolver
                ->expects($this->once())
                ->method('isFullFledged')
                ->willReturn(false)
            ;
            $trustResolver
                ->expects($this->once())
                ->method('isRememberMe')
                ->willReturn(true)
            ;
        } else {
            if (method_exists(AuthenticationTrustResolverInterface::class, 'isAuthenticated')) {
                $trustResolver
                    ->method('isAuthenticated')
                    ->willReturn(false)
                ;
            } else {
                $trustResolver
                    ->method('isAnonymous')
                    ->willReturn(true);
            }

            $trustResolver
                ->expects($this->once())
                ->method('isFullFledged')
                ->willReturn(false)
            ;
            $trustResolver
                ->expects($this->once())
                ->method('isRememberMe')
                ->willReturn(false)
            ;
        }

        return new SecurityIdentityRetrievalStrategy($roleHierarchy, $trustResolver);
    }
}

class CustomUserImpl implements UserInterface
{
    protected $name;

    public function __construct($name)
    {
        $this->name = $name;
    }

    public function __toString()
    {
        return $this->name;
    }

    public function getRoles(): array
    {
        return [];
    }

    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return $this->name;
    }

    public function getPassword()
    {
        return null;
    }

    public function getSalt()
    {
        return null;
    }

    public function getUsername(): string
    {
        return $this->getUserIdentifier();
    }
}
