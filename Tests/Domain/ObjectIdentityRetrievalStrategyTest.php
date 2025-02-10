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

use Symfony\Component\Security\Acl\Domain\ObjectIdentityRetrievalStrategy;

class ObjectIdentityRetrievalStrategyTest extends \PHPUnit\Framework\TestCase
{
    public function testGetObjectIdentityReturnsNullForInvalidDomainObject()
    {
        $strategy = new ObjectIdentityRetrievalStrategy();
        $this->assertNull($strategy->getObjectIdentity(new \stdClass()));
    }

    public function testGetObjectIdentity()
    {
        $strategy = new ObjectIdentityRetrievalStrategy();
        $domainObject = new DomainObject();
        $objectIdentity = $strategy->getObjectIdentity($domainObject);

        $this->assertEquals($domainObject->getId(), $objectIdentity->getIdentifier());
        $this->assertEquals($domainObject::class, $objectIdentity->getType());
    }
}

class DomainObject
{
    public function getId()
    {
        return 'foo';
    }
}
