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
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\NoAceFoundException;
use Symfony\Component\Security\Acl\Model\AuditLoggerInterface;

class PermissionGrantingStrategyTest extends TestCase
{
    public function testIsGrantedObjectAcesHavePriority()
    {
        $strategy = new PermissionGrantingStrategy();
        $acl = $this->getAcl($strategy);
        $sid = new UserSecurityIdentity('johannes', 'Foo');

        $acl->insertClassAce($sid, 1);
        $acl->insertObjectAce($sid, 1, 0, false);
        $this->assertFalse($strategy->isGranted($acl, [1], [$sid]));
    }

    public function testIsGrantedFallsBackToClassAcesIfNoApplicableObjectAceWasFound()
    {
        $strategy = new PermissionGrantingStrategy();
        $acl = $this->getAcl($strategy);
        $sid = new UserSecurityIdentity('johannes', 'Foo');

        $acl->insertClassAce($sid, 1);
        $this->assertTrue($strategy->isGranted($acl, [1], [$sid]));
    }

    public function testIsGrantedFavorsLocalAcesOverParentAclAces()
    {
        $strategy = new PermissionGrantingStrategy();
        $sid = new UserSecurityIdentity('johannes', 'Foo');

        $acl = $this->getAcl($strategy);
        $acl->insertClassAce($sid, 1);

        $parentAcl = $this->getAcl($strategy);
        $acl->setParentAcl($parentAcl);
        $parentAcl->insertClassAce($sid, 1, 0, false);

        $this->assertTrue($strategy->isGranted($acl, [1], [$sid]));
    }

    public function testIsGrantedFallsBackToParentAcesIfNoLocalAcesAreApplicable()
    {
        $strategy = new PermissionGrantingStrategy();
        $sid = new UserSecurityIdentity('johannes', 'Foo');
        $anotherSid = new UserSecurityIdentity('ROLE_USER', 'Foo');

        $acl = $this->getAcl($strategy);
        $acl->insertClassAce($anotherSid, 1, 0, false);

        $parentAcl = $this->getAcl($strategy);
        $acl->setParentAcl($parentAcl);
        $parentAcl->insertClassAce($sid, 1);

        $this->assertTrue($strategy->isGranted($acl, [1], [$sid]));
    }

    public function testIsGrantedReturnsExceptionIfNoAceIsFound()
    {
        $strategy = new PermissionGrantingStrategy();
        $acl = $this->getAcl($strategy);
        $sid = new UserSecurityIdentity('johannes', 'Foo');

        $this->expectException(NoAceFoundException::class);
        $strategy->isGranted($acl, [1], [$sid]);
    }

    public function testIsGrantedFirstApplicableEntryMakesUltimateDecisionForPermissionIdentityCombination()
    {
        $strategy = new PermissionGrantingStrategy();
        $acl = $this->getAcl($strategy);
        $sid = new UserSecurityIdentity('johannes', 'Foo');
        $aSid = new RoleSecurityIdentity('ROLE_USER');

        $acl->insertClassAce($aSid, 1);
        $acl->insertClassAce($sid, 1, 1, false);
        $acl->insertClassAce($sid, 1, 2);
        $this->assertFalse($strategy->isGranted($acl, [1], [$sid, $aSid]));

        $acl->insertObjectAce($sid, 1, 0, false);
        $acl->insertObjectAce($aSid, 1, 1);
        $this->assertFalse($strategy->isGranted($acl, [1], [$sid, $aSid]));
    }

    public function testIsGrantedCallsAuditLoggerOnGrant()
    {
        $strategy = new PermissionGrantingStrategy();
        $acl = $this->getAcl($strategy);
        $sid = new UserSecurityIdentity('johannes', 'Foo');

        $logger = $this->createMock(AuditLoggerInterface::class);
        $logger
            ->expects($this->once())
            ->method('logIfNeeded')
        ;
        $strategy->setAuditLogger($logger);

        $acl->insertObjectAce($sid, 1);
        $acl->updateObjectAuditing(0, true, false);

        $this->assertTrue($strategy->isGranted($acl, [1], [$sid]));
    }

    public function testIsGrantedCallsAuditLoggerOnDeny()
    {
        $strategy = new PermissionGrantingStrategy();
        $acl = $this->getAcl($strategy);
        $sid = new UserSecurityIdentity('johannes', 'Foo');

        $logger = $this->createMock(AuditLoggerInterface::class);
        $logger
            ->expects($this->once())
            ->method('logIfNeeded')
        ;
        $strategy->setAuditLogger($logger);

        $acl->insertObjectAce($sid, 1, 0, false);
        $acl->updateObjectAuditing(0, false, true);

        $this->assertFalse($strategy->isGranted($acl, [1], [$sid]));
    }

    /**
     * @dataProvider getAllStrategyTests
     */
    public function testIsGrantedStrategies($maskStrategy, $aceMask, $requiredMask, $result)
    {
        $strategy = new PermissionGrantingStrategy();
        $acl = $this->getAcl($strategy);
        $sid = new UserSecurityIdentity('johannes', 'Foo');

        $acl->insertObjectAce($sid, $aceMask, 0, true, $maskStrategy);

        if (false === $result) {
            $this->expectException(NoAceFoundException::class);
            $this->expectExceptionMessage('No applicable ACE was found.');

            $strategy->isGranted($acl, [$requiredMask], [$sid]);
        } else {
            $this->assertTrue($strategy->isGranted($acl, [$requiredMask], [$sid]));
        }
    }

    public function getAllStrategyTests()
    {
        return [
            ['all', 1 << 0 | 1 << 1, 1 << 0, true],
            ['all', 1 << 0 | 1 << 1, 1 << 2, false],
            ['all', 1 << 0 | 1 << 10, 1 << 0 | 1 << 10, true],
            ['all', 1 << 0 | 1 << 1, 1 << 0 | 1 << 1 || 1 << 2, false],
            ['any', 1 << 0 | 1 << 1, 1 << 0, true],
            ['any', 1 << 0 | 1 << 1, 1 << 0 | 1 << 2, true],
            ['any', 1 << 0 | 1 << 1, 1 << 2, false],
            ['equal', 1 << 0 | 1 << 1, 1 << 0, false],
            ['equal', 1 << 0 | 1 << 1, 1 << 1, false],
            ['equal', 1 << 0 | 1 << 1, 1 << 0 | 1 << 1, true],
        ];
    }

    protected function getAcl($strategy)
    {
        static $id = 1;

        return new Acl($id++, new ObjectIdentity(1, 'Foo'), $strategy, [], true);
    }
}
