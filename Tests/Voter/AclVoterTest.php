<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Acl\Tests\Voter;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Exception\NoAceFoundException;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\AclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityRetrievalStrategyInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityRetrievalStrategyInterface;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface;
use Symfony\Component\Security\Acl\Voter\AclVoter;
use Symfony\Component\Security\Acl\Voter\FieldVote;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

class AclVoterTest extends TestCase
{
    /**
     * @dataProvider getSupportsAttributeTests
     */
    public function testSupportsAttribute($attribute, $supported)
    {
        [$voter, , $permissionMap] = $this->getVoter(true, false);

        $permissionMap
            ->expects($this->once())
            ->method('contains')
            ->with($this->identicalTo($attribute))
            ->willReturn($supported)
        ;

        $this->assertSame($supported, $voter->supportsAttribute($attribute));
    }

    /**
     * @dataProvider getSupportsAttributeNonStringTests
     */
    public function testSupportsAttributeNonString($attribute)
    {
        [$voter] = $this->getVoter(true, false);

        $this->assertFalse($voter->supportsAttribute($attribute));
    }

    public function getSupportsAttributeTests()
    {
        return [
            ['foo', true],
            ['foo', false],
        ];
    }

    public function getSupportsAttributeNonStringTests()
    {
        return [
            [new \stdClass()],
            [1],
            [true],
            [[]],
        ];
    }

    /**
     * @dataProvider getSupportsClassTests
     */
    public function testSupportsClass($class)
    {
        [$voter] = $this->getVoter();

        $this->assertTrue($voter->supportsClass($class));
    }

    public function getSupportsClassTests()
    {
        return [
            ['foo'],
            ['bar'],
            ['moo'],
        ];
    }

    public function testVote()
    {
        [$voter, , $permissionMap] = $this->getVoter();
        $permissionMap
            ->expects($this->atLeastOnce())
            ->method('getMasks')
            ->willReturn(null)
        ;

        $this->assertSame(VoterInterface::ACCESS_ABSTAIN, $voter->vote($this->getToken(), null, ['VIEW', 'EDIT', 'DELETE']));
    }

    /**
     * @dataProvider getTrueFalseTests
     */
    public function testVoteWhenNoObjectIsPassed($allowIfObjectIdentityUnavailable)
    {
        [$voter, , $permissionMap] = $this->getVoter($allowIfObjectIdentityUnavailable);
        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->willReturn([])
        ;

        if ($allowIfObjectIdentityUnavailable) {
            $vote = VoterInterface::ACCESS_GRANTED;
        } else {
            $vote = VoterInterface::ACCESS_ABSTAIN;
        }

        $this->assertSame($vote, $voter->vote($this->getToken(), null, ['VIEW']));
    }

    /**
     * @dataProvider getTrueFalseTests
     */
    public function testVoteWhenOidStrategyReturnsNull($allowIfUnavailable)
    {
        [$voter, , $permissionMap, $oidStrategy] = $this->getVoter($allowIfUnavailable);
        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->willReturn([])
        ;

        $oidStrategy
            ->expects($this->once())
            ->method('getObjectIdentity')
            ->willReturn(null)
        ;

        if ($allowIfUnavailable) {
            $vote = VoterInterface::ACCESS_GRANTED;
        } else {
            $vote = VoterInterface::ACCESS_ABSTAIN;
        }

        $this->assertSame($vote, $voter->vote($this->getToken(), new \stdClass(), ['VIEW']));
    }

    public function getTrueFalseTests()
    {
        return [[true], [false]];
    }

    public function testVoteNoAclFound()
    {
        [$voter, $provider, $permissionMap, $oidStrategy, $sidStrategy] = $this->getVoter();

        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->willReturn([])
        ;

        $oidStrategy
            ->expects($this->once())
            ->method('getObjectIdentity')
            ->willReturn($oid = new ObjectIdentity('1', 'Foo'))
        ;

        $sidStrategy
            ->expects($this->once())
            ->method('getSecurityIdentities')
            ->willReturn($sids = [new UserSecurityIdentity('johannes', 'Foo'), new RoleSecurityIdentity('ROLE_FOO')])
        ;

        $provider
            ->expects($this->once())
            ->method('findAcl')
            ->with($this->equalTo($oid), $this->equalTo($sids))
            ->will($this->throwException(new AclNotFoundException('Not found.')))
        ;

        $this->assertSame(VoterInterface::ACCESS_DENIED, $voter->vote($this->getToken(), new \stdClass(), ['VIEW']));
    }

    /**
     * @dataProvider getTrueFalseTests
     */
    public function testVoteGrantsAccess($grant)
    {
        [$voter, $provider, $permissionMap, $oidStrategy, $sidStrategy] = $this->getVoter();

        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->with($this->equalTo('VIEW'))
            ->willReturn($masks = [1, 2, 3])
        ;

        $oidStrategy
            ->expects($this->once())
            ->method('getObjectIdentity')
            ->willReturn($oid = new ObjectIdentity('1', 'Foo'))
        ;

        $sidStrategy
            ->expects($this->once())
            ->method('getSecurityIdentities')
            ->willReturn($sids = [new UserSecurityIdentity('johannes', 'Foo'), new RoleSecurityIdentity('ROLE_FOO')])
        ;

        $provider
            ->expects($this->once())
            ->method('findAcl')
            ->with($this->equalTo($oid), $this->equalTo($sids))
            ->willReturn($acl = $this->createMock(AclInterface::class))
        ;

        $acl
            ->expects($this->once())
            ->method('isGranted')
            ->with($this->identicalTo($masks), $this->equalTo($sids), $this->isFalse())
            ->willReturn($grant)
        ;

        if ($grant) {
            $vote = VoterInterface::ACCESS_GRANTED;
        } else {
            $vote = VoterInterface::ACCESS_DENIED;
        }

        $this->assertSame($vote, $voter->vote($this->getToken(), new \stdClass(), ['VIEW']));
    }

    public function testVoteNoAceFound()
    {
        [$voter, $provider, $permissionMap, $oidStrategy, $sidStrategy] = $this->getVoter();

        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->with($this->equalTo('VIEW'))
            ->willReturn($masks = [1, 2, 3])
        ;

        $oidStrategy
            ->expects($this->once())
            ->method('getObjectIdentity')
            ->willReturn($oid = new ObjectIdentity('1', 'Foo'))
        ;

        $sidStrategy
            ->expects($this->once())
            ->method('getSecurityIdentities')
            ->willReturn($sids = [new UserSecurityIdentity('johannes', 'Foo'), new RoleSecurityIdentity('ROLE_FOO')])
        ;

        $provider
            ->expects($this->once())
            ->method('findAcl')
            ->with($this->equalTo($oid), $this->equalTo($sids))
            ->willReturn($acl = $this->createMock(AclInterface::class))
        ;

        $acl
            ->expects($this->once())
            ->method('isGranted')
            ->with($this->identicalTo($masks), $this->equalTo($sids), $this->isFalse())
            ->will($this->throwException(new NoAceFoundException('No ACE')))
        ;

        $this->assertSame(VoterInterface::ACCESS_DENIED, $voter->vote($this->getToken(), new \stdClass(), ['VIEW']));
    }

    /**
     * @dataProvider getTrueFalseTests
     */
    public function testVoteGrantsFieldAccess($grant)
    {
        [$voter, $provider, $permissionMap, $oidStrategy, $sidStrategy] = $this->getVoter();

        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->with($this->equalTo('VIEW'))
            ->willReturn($masks = [1, 2, 3])
        ;

        $oidStrategy
            ->expects($this->once())
            ->method('getObjectIdentity')
            ->willReturn($oid = new ObjectIdentity('1', 'Foo'))
        ;

        $sidStrategy
            ->expects($this->once())
            ->method('getSecurityIdentities')
            ->willReturn($sids = [new UserSecurityIdentity('johannes', 'Foo'), new RoleSecurityIdentity('ROLE_FOO')])
        ;

        $provider
            ->expects($this->once())
            ->method('findAcl')
            ->with($this->equalTo($oid), $this->equalTo($sids))
            ->willReturn($acl = $this->createMock(AclInterface::class))
        ;

        $acl
            ->expects($this->once())
            ->method('isFieldGranted')
            ->with($this->identicalTo('foo'), $this->identicalTo($masks), $this->equalTo($sids), $this->isFalse())
            ->willReturn($grant)
        ;

        if ($grant) {
            $vote = VoterInterface::ACCESS_GRANTED;
        } else {
            $vote = VoterInterface::ACCESS_DENIED;
        }

        $this->assertSame($vote, $voter->vote($this->getToken(), new FieldVote(new \stdClass(), 'foo'), ['VIEW']));
    }

    public function testVoteNoFieldAceFound()
    {
        [$voter, $provider, $permissionMap, $oidStrategy, $sidStrategy] = $this->getVoter();

        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->with($this->equalTo('VIEW'))
            ->willReturn($masks = [1, 2, 3])
        ;

        $oidStrategy
            ->expects($this->once())
            ->method('getObjectIdentity')
            ->willReturn($oid = new ObjectIdentity('1', 'Foo'))
        ;

        $sidStrategy
            ->expects($this->once())
            ->method('getSecurityIdentities')
            ->willReturn($sids = [new UserSecurityIdentity('johannes', 'Foo'), new RoleSecurityIdentity('ROLE_FOO')])
        ;

        $provider
            ->expects($this->once())
            ->method('findAcl')
            ->with($this->equalTo($oid), $this->equalTo($sids))
            ->willReturn($acl = $this->createMock(AclInterface::class))
        ;

        $acl
            ->expects($this->once())
            ->method('isFieldGranted')
            ->with($this->identicalTo('foo'), $this->identicalTo($masks), $this->equalTo($sids), $this->isFalse())
            ->will($this->throwException(new NoAceFoundException('No ACE')))
        ;

        $this->assertSame(VoterInterface::ACCESS_DENIED, $voter->vote($this->getToken(), new FieldVote(new \stdClass(), 'foo'), ['VIEW']));
    }

    public function testWhenReceivingAnObjectIdentityInterfaceWeDontRetrieveANewObjectIdentity()
    {
        [$voter, $provider, $permissionMap, $oidStrategy, $sidStrategy] = $this->getVoter();

        $oid = new ObjectIdentity('someID', 'someType');

        $permissionMap
            ->expects($this->once())
            ->method('getMasks')
            ->with($this->equalTo('VIEW'))
            ->willReturn($masks = [1, 2, 3])
        ;

        $oidStrategy
            ->expects($this->never())
            ->method('getObjectIdentity')
        ;

        $sidStrategy
            ->expects($this->once())
            ->method('getSecurityIdentities')
            ->willReturn($sids = [new UserSecurityIdentity('johannes', 'Foo'), new RoleSecurityIdentity('ROLE_FOO')])
        ;

        $provider
            ->expects($this->once())
            ->method('findAcl')
            ->with($this->equalTo($oid), $this->equalTo($sids))
            ->willReturn($acl = $this->createMock(AclInterface::class))
        ;

        $acl
            ->expects($this->once())
            ->method('isGranted')
            ->with($this->identicalTo($masks), $this->equalTo($sids), $this->isFalse())
            ->will($this->throwException(new NoAceFoundException('No ACE')))
        ;

        $voter->vote($this->getToken(), $oid, ['VIEW']);
    }

    protected function getToken()
    {
        return $this->createMock(TokenInterface::class);
    }

    protected function getVoter($allowIfObjectIdentityUnavailable = true, $alwaysContains = true)
    {
        $provider = $this->createMock(AclProviderInterface::class);
        $permissionMap = $this->createMock(PermissionMapInterface::class);
        $oidStrategy = $this->createMock(ObjectIdentityRetrievalStrategyInterface::class);
        $sidStrategy = $this->createMock(SecurityIdentityRetrievalStrategyInterface::class);

        if ($alwaysContains) {
            $permissionMap
                ->expects($this->any())
                ->method('contains')
                ->willReturn(true);
        }

        return [
            new AclVoter($provider, $oidStrategy, $sidStrategy, $permissionMap, null, $allowIfObjectIdentityUnavailable),
            $provider,
            $permissionMap,
            $oidStrategy,
            $sidStrategy,
        ];
    }
}
