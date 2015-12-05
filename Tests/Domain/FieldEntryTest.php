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

class FieldEntryTest extends \PHPUnit_Framework_TestCase
{
    public function testConstructor()
    {
        $ace = $this->getAce();

        $this->assertEquals('foo', $ace->getField());
    }

    public function testSerializeUnserializeSameSecurityIdentity()
    {
        $sid = $this->getSid();

        $aceFirst = $this->getAce(null, $sid);
        $aceSecond = $this->getAce(null, $sid);

        /** @var FieldEntry $uAceFirst */
        /** @var FieldEntry $uAceSecond */
        list($uAceFirst, $uAceSecond) = unserialize(serialize(array($aceFirst, $aceSecond)));

        $this->assertInstanceOf('Symfony\Component\Security\Acl\Model\SecurityIdentityInterface', $uAceFirst->getSecurityIdentity());
        $this->assertSame($uAceFirst->getSecurityIdentity(), $uAceSecond->getSecurityIdentity());
    }

    public function testUnserializeLegacy()
    {
        $serialized = 'C:48:"Symfony\Component\Security\Acl\Domain\FieldEntry":300:{a:2:{i:0;s:5:"field";i:1;s:265:"a:7:{i:0;s:4:"mask";i:1;i:1;i:2;O:20:"SecurityEdentityMock":2:{s:48:" SecurityEdentityMock __phpunit_invocationMocker";N;s:46:" SecurityEdentityMock __phpunit_originalObject";N;}i:3;s:8:"strategy";i:4;s:12:"auditFailure";i:5;s:12:"auditSuccess";i:6;s:8:"granting";}";}}';
        $ace = unserialize($serialized);
        $this->assertNull($ace->getAcl());
        $this->assertEquals(1, $ace->getId());
        $this->assertEquals('field', $ace->getField());
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
        return $this->getMock('Symfony\Component\Security\Acl\Model\AclInterface');
    }

    protected function getSid()
    {
        return $this->getMock('Symfony\Component\Security\Acl\Model\SecurityIdentityInterface');
    }
}
