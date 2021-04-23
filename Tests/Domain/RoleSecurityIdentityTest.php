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

use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Core\Role\Role;

class RoleSecurityIdentityTest extends \PHPUnit\Framework\TestCase
{
    public function testConstructor()
    {
        $id = new RoleSecurityIdentity('ROLE_FOO');

        $this->assertEquals('ROLE_FOO', $id->getRole());
    }

    /**
     * @group legacy
     */
    public function testConstructorWithRoleInstance()
    {
        if (!class_exists(\Symfony\Component\Security\Core\Role\Role::class)) {
            $this->markTestSkipped();
        }

        $id = new RoleSecurityIdentity(new Role('ROLE_FOO'));

        $this->assertEquals('ROLE_FOO', $id->getRole());
    }

    /**
     * @dataProvider getCompareData
     */
    public function testEquals($id1, $id2, $equal)
    {
        if ($equal) {
            $this->assertTrue($id1->equals($id2));
        } else {
            $this->assertFalse($id1->equals($id2));
        }
    }

    /**
     * @group legacy
     */
    public function testDeprecatedRoleClassEquals()
    {
        if (!class_exists(Role::class)) {
            $this->markTestSkipped();
        }

        $id1 = new RoleSecurityIdentity('ROLE_FOO');
        $id2 = new RoleSecurityIdentity(new Role('ROLE_FOO'));
        $this->assertTrue($id1->equals($id2));
    }

    public function getCompareData()
    {
        return [
            [new RoleSecurityIdentity('ROLE_FOO'), new RoleSecurityIdentity('ROLE_FOO'), true],
            [new RoleSecurityIdentity('ROLE_USER'), new RoleSecurityIdentity('ROLE_FOO'), false],
            [new RoleSecurityIdentity('ROLE_FOO'), new UserSecurityIdentity('ROLE_FOO', 'Foo'), false],
        ];
    }
}
