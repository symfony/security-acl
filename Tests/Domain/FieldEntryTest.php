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

use Symfony\Component\Security\Acl\Domain\FieldEntry;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

class FieldEntryTest extends \PHPUnit\Framework\TestCase
{
    public function testConstructor()
    {
        $ace = $this->getAce();

        $this->assertEquals('foo', $ace->getField());
    }

    public function testSerializeUnserialize()
    {
        $ace = $this->getAce();

        $serialized = serialize($ace);
        $uAce = unserialize($serialized);

        $this->assertNull($uAce->getAcl());
        $this->assertInstanceOf('Symfony\Component\Security\Acl\Model\SecurityIdentityInterface', $uAce->getSecurityIdentity());
        $this->assertEquals($ace->getId(), $uAce->getId());
        $this->assertEquals($ace->getField(), $uAce->getField());
        $this->assertEquals($ace->getMask(), $uAce->getMask());
        $this->assertEquals($ace->getStrategy(), $uAce->getStrategy());
        $this->assertEquals($ace->isGranting(), $uAce->isGranting());
        $this->assertEquals($ace->isAuditSuccess(), $uAce->isAuditSuccess());
        $this->assertEquals($ace->isAuditFailure(), $uAce->isAuditFailure());
    }

    public function testSerializeUnserializeMoreAceWithSameSecurityIdentity()
    {
        $sid = $this->getSid();

        $aceFirst = $this->getAce(null, $sid);
        $aceSecond = $this->getAce(null, $sid);

        // as used in DoctrineAclCache::putInCache (line 142)
        $serialized = serialize([[
            'fieldOne' => [$aceFirst],
            'fieldTwo' => [$aceSecond],
        ]]);

        $unserialized = unserialize($serialized);
        $uAceFirst = $unserialized[0]['fieldOne'][0];
        $uAceSecond = $unserialized[0]['fieldTwo'][0];

        $this->assertInstanceOf(SecurityIdentityInterface::class, $uAceFirst->getSecurityIdentity());
        $this->assertInstanceOf(SecurityIdentityInterface::class, $uAceSecond->getSecurityIdentity());
    }

    protected function getAce($acl = null, $sid = null)
    {
        if (null === $acl) {
            $acl = $this->getAcl();
        }
        if (null === $sid) {
            $sid = $this->getSid();
        }

        return new FieldEntry(
            123,
            $acl,
            'foo',
            $sid,
            'foostrat',
            123456,
            true,
            false,
            true
        );
    }

    protected function getAcl()
    {
        return $this->createMock('Symfony\Component\Security\Acl\Model\AclInterface');
    }

    protected function getSid()
    {
        return $this->createMock('Symfony\Component\Security\Acl\Model\SecurityIdentityInterface');
    }
}
