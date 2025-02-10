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

namespace Symfony\Component\Security\Acl\Tests\Domain;

use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Tests\Fixtures\Account;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class UserSecurityIdentityTest extends \PHPUnit\Framework\TestCase
{
    public function testConstructor()
    {
        $id = new UserSecurityIdentity('foo', 'Foo');

        $this->assertEquals('foo', $id->getUsername());
        $this->assertEquals('Foo', $id->getClass());
    }

    // Test that constructor never changes the type, even for proxies
    public function testConstructorWithProxy()
    {
        $id = new UserSecurityIdentity('foo', 'Acme\DemoBundle\Proxy\__CG__\Symfony\Component\Security\Acl\Tests\Domain\Foo');

        $this->assertEquals('foo', $id->getUsername());
        $this->assertEquals('Acme\DemoBundle\Proxy\__CG__\Symfony\Component\Security\Acl\Tests\Domain\Foo', $id->getClass());
    }

    /**
     * @dataProvider getCompareData
     */
    public function testEquals(UserSecurityIdentity $id1, SecurityIdentityInterface $id2, bool $equal)
    {
        $this->assertSame($equal, $id1->equals($id2));
    }

    public function getCompareData(): array
    {
        $account = new Account('foo');

        $token = $this->createMock(TokenInterface::class);
        $token
            ->expects($this->any())
            ->method('getUser')
            ->willReturn($account)
        ;

        return [
            [new UserSecurityIdentity('foo', 'Foo'), new UserSecurityIdentity('foo', 'Foo'), true],
            [new UserSecurityIdentity('foo', 'Bar'), new UserSecurityIdentity('foo', 'Foo'), false],
            [new UserSecurityIdentity('foo', 'Foo'), new UserSecurityIdentity('bar', 'Foo'), false],
            [new UserSecurityIdentity('foo', 'Foo'), UserSecurityIdentity::fromAccount($account), false],
            [new UserSecurityIdentity('bla', 'Foo'), new UserSecurityIdentity('blub', 'Foo'), false],
            [new UserSecurityIdentity('foo', 'Foo'), new RoleSecurityIdentity('foo'), false],
            [new UserSecurityIdentity('foo', 'Foo'), UserSecurityIdentity::fromToken($token), false],
            [new UserSecurityIdentity('foo', Account::class), UserSecurityIdentity::fromToken($token), true],
        ];
    }
}
