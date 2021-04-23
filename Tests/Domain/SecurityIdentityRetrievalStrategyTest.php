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

use Symfony\Bridge\PhpUnit\ExpectDeprecationTrait;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\SecurityIdentityRetrievalStrategy;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class SecurityIdentityRetrievalStrategyTest extends \PHPUnit\Framework\TestCase
{
    use ExpectDeprecationTrait;

    /**
     * @dataProvider getSecurityIdentityRetrievalTests
     */
    public function testGetSecurityIdentities($user, array $roles, $authenticationStatus, array $sids)
    {
        if (class_exists(Role::class)) {
            $this->markTestSkipped();

            return;
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

            $token = $this->getMockBuilder(TokenInterface::class)
                ->setMockClassName($class)
                ->getMock();
        }

        $strategy = $this->getStrategy($roles, $authenticationStatus, false);

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

    /**
     * @group legacy
     * @dataProvider getSecurityIdentityRetrievalTests
     */
    public function testLegacyGetSecurityIdentities($user, array $roles, $authenticationStatus, array $sids)
    {
        if (!class_exists(Role::class)) {
            $this->markTestSkipped();

            return;
        }

        if (method_exists(TokenInterface::class, 'getRoleNames')) {
            $this->expectDeprecation('The "Symfony\Component\Security\Core\Role\Role" class is deprecated since Symfony 4.3 and will be removed in 5.0. Use strings as roles instead.');
            $this->expectDeprecation('The Symfony\Component\Security\Core\Authentication\Token\TokenInterface::getRoles method is deprecated (since Symfony 4.3, use the getRoleNames() method instead).');
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

            $token = $this->getMockBuilder(TokenInterface::class)
                ->setMockClassName($class)
                ->getMock();
        }

        $strategy = $this->getStrategy($roles, $authenticationStatus, true);

        $token
            ->expects($this->once())
            ->method('getRoles')
            ->willReturn([new Role('foo')])
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

    public function getSecurityIdentityRetrievalTests()
    {
        return [
            [$this->getAccount('johannes', 'FooUser'), ['ROLE_USER', 'ROLE_SUPERADMIN'], 'fullFledged', [
                new UserSecurityIdentity('johannes', 'FooUser'),
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
                new UserSecurityIdentity('johannes', 'Symfony\Component\Security\Acl\Tests\Domain\CustomUserImpl'),
                new RoleSecurityIdentity('ROLE_FOO'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_FULLY'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_REMEMBERED'),
                new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY'),
            ]],
            [$this->getAccount('foo', 'FooBarUser'), ['ROLE_FOO'], 'rememberMe', [
                new UserSecurityIdentity('foo', 'FooBarUser'),
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

    protected function getAccount($username, $class)
    {
        $account = $this->getMockBuilder(UserInterface::class)
            ->setMockClassName($class)
            ->getMock()
        ;
        $account
            ->expects($this->any())
            ->method('getUsername')
            ->willReturn($username)
        ;

        return $account;
    }

    protected function getStrategy(array $roles = [], $authenticationStatus = 'fullFledged', $isBC = false)
    {
        $roleHierarchyBuilder = $this->getMockBuilder('Symfony\Component\Security\Core\Role\RoleHierarchyInterface')
            ->disableProxyingToOriginalMethods()
            ->disableOriginalConstructor();

        if ($isBC) {
            $roleHierarchy = $roleHierarchyBuilder->setMethods(['getReachableRoles'])
                ->getMockForAbstractClass();

            $roleHierarchy
                ->expects($this->any())
                ->method('getReachableRoles')
                ->with($this->equalTo([new Role('foo')]))
                ->willReturn($roles);
        } else {
            $roleHierarchy = $roleHierarchyBuilder->setMethods(['getReachableRoleNames'])
                ->getMockForAbstractClass();

            $roleHierarchy
                ->expects($this->any())
                ->method('getReachableRoleNames')
                ->with($this->equalTo(['foo']))
                ->willReturn($roles);
        }

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
