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

use PHPUnit\Framework\Assert;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\SecurityIdentityRetrievalStrategy;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Tests\Fixtures\Account;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;

class SecurityIdentityRetrievalStrategyTest extends TestCase
{
    /**
     * @dataProvider getSecurityIdentityRetrievalTests
     */
    public function testGetSecurityIdentities($user, array $roles, string $authenticationStatus, array $sids)
    {
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
                $this->fail(sprintf('Expected SID at index %d, but there was none.', true));
            }

            if (false === $sids[$index]->equals($extractedSid)) {
                $this->fail(sprintf('Index: %d, expected SID "%s", but got "%s".', $index, $sids[$index], $extractedSid));
            }
        }
    }

    public function getSecurityIdentityRetrievalTests(): array
    {
        return [
            [new Account('johannes'), ['ROLE_USER', 'ROLE_SUPERADMIN'], 'fullFledged', [
                new UserSecurityIdentity('johannes', Account::class),
                new RoleSecurityIdentity('ROLE_USER'),
                new RoleSecurityIdentity('ROLE_SUPERADMIN'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_FULLY'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'),
            ]],
            ['johannes', ['ROLE_FOO'], 'fullFledged', [
                new UserSecurityIdentity('johannes', 'MyCustomTokenImpl'),
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_FULLY'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'),
            ]],
            [new CustomUserImpl('johannes'), ['ROLE_FOO'], 'fullFledged', [
                new UserSecurityIdentity('johannes', CustomUserImpl::class),
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_FULLY'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'),
            ]],
            [new Account('foo'), ['ROLE_FOO'], 'rememberMe', [
                new UserSecurityIdentity('foo', Account::class),
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'),
            ]],
            ['guest', ['ROLE_FOO'], 'anonymous', [
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'),
            ]],
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
                Assert::assertSame(['foo'], $roles);

                return $this->roles;
            }
        };

        $trustResolver = $this->createMock(AuthenticationTrustResolverInterface::class);

        $trustResolver
            ->method('isAnonymous')
            ->willReturn('anonymous' === $authenticationStatus)
        ;

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
            $trustResolver
                ->method('isAnonymous')
                ->willReturn(true)
            ;
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

class CustomUserImpl
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
}
