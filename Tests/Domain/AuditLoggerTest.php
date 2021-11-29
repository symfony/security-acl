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
use Symfony\Component\Security\Acl\Domain\AuditLogger;
use Symfony\Component\Security\Acl\Tests\Fixtures\SerializableAuditableEntryInterface;

class AuditLoggerTest extends TestCase
{
    /**
     * @dataProvider getTestLogData
     */
    public function testLogIfNeeded($granting, $audit)
    {
        $logger = $this->getLogger();
        $ace = $this->getEntry();

        if (true === $granting) {
            $ace
                ->expects($this->once())
                ->method('isAuditSuccess')
                ->willReturn($audit)
            ;

            $ace
               ->expects($this->never())
               ->method('isAuditFailure')
            ;
        } else {
            $ace
                ->expects($this->never())
                ->method('isAuditSuccess')
            ;

            $ace
                ->expects($this->once())
                ->method('isAuditFailure')
                ->willReturn($audit)
            ;
        }

        if (true === $audit) {
            $logger
               ->expects($this->once())
               ->method('doLog')
               ->with($this->equalTo($granting), $this->equalTo($ace))
            ;
        } else {
            $logger
                ->expects($this->never())
                ->method('doLog')
            ;
        }

        $logger->logIfNeeded($granting, $ace);
    }

    public function getTestLogData()
    {
        return [
            [true, false],
            [true, true],
            [false, false],
            [false, true],
        ];
    }

    protected function getEntry()
    {
        return $this->createMock(SerializableAuditableEntryInterface::class);
    }

    protected function getLogger()
    {
        return $this->getMockForAbstractClass(AuditLogger::class);
    }
}
