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
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

class RoleSecurityIdentityTest extends TestCase
{
    public function testConstructor()
    {
        $id = new RoleSecurityIdentity('ROLE_FOO');

        $this->assertEquals('ROLE_FOO', $id->getRole());
    }

    /**
     * @dataProvider getCompareData
     */
    public function testEquals(RoleSecurityIdentity $id1, SecurityIdentityInterface $id2, bool $equal)
    {
        if ($equal) {
            $this->assertTrue($id1->equals($id2));
        } else {
            $this->assertFalse($id1->equals($id2));
        }
    }

    public function getCompareData(): array
    {
        return [
            [new RoleSecurityIdentity('ROLE_FOO'), new RoleSecurityIdentity('ROLE_FOO'), true],
            [new RoleSecurityIdentity('ROLE_USER'), new RoleSecurityIdentity('ROLE_FOO'), false],
            [new RoleSecurityIdentity('ROLE_FOO'), new UserSecurityIdentity('ROLE_FOO', 'Foo'), false],
        ];
    }
}
