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

namespace Symfony\Component\Security\Acl\Tests\Dbal;

use Doctrine\DBAL\Configuration;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\DefaultSchemaManagerFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Acl\Dbal\AclProvider;
use Symfony\Component\Security\Acl\Dbal\Schema;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Domain\Entry;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Exception\NotAllAclsFoundException;

/**
 * @requires extension pdo_sqlite
 */
class AclProviderTest extends TestCase
{
    private $connection;

    /**
     * @expectedMessage There is no ACL for the given object identity.
     */
    public function testFindAclThrowsExceptionWhenNoAclExists()
    {
        $this->expectException(AclNotFoundException::class);

        $this->getProvider()->findAcl(new ObjectIdentity('foo', 'foo'));
    }

    public function testFindAclsThrowsExceptionUnlessAnACLIsFoundForEveryOID()
    {
        $oids = [];
        $oids[] = new ObjectIdentity('1', 'foo');
        $oids[] = new ObjectIdentity('foo', 'foo');

        try {
            $this->getProvider()->findAcls($oids);

            $this->fail('Provider did not throw an expected exception.');
        } catch (\Exception $e) {
            $this->assertInstanceOf(AclNotFoundException::class, $e);
            $this->assertInstanceOf(NotAllAclsFoundException::class, $e);

            $partialResult = $e->getPartialResult();
            $this->assertTrue($partialResult->contains($oids[0]));
            $this->assertFalse($partialResult->contains($oids[1]));
        }
    }

    public function testFindAcls()
    {
        $oids = [];
        $oids[] = new ObjectIdentity('1', 'foo');
        $oids[] = new ObjectIdentity('2', 'foo');

        $provider = $this->getProvider();

        $acls = $provider->findAcls($oids);
        $this->assertInstanceOf('SplObjectStorage', $acls);
        $this->assertCount(2, $acls);
        $this->assertInstanceOf(Acl::class, $acl0 = $acls->offsetGet($oids[0]));
        $this->assertInstanceOf(Acl::class, $acl1 = $acls->offsetGet($oids[1]));
        $this->assertTrue($oids[0]->equals($acl0->getObjectIdentity()));
        $this->assertTrue($oids[1]->equals($acl1->getObjectIdentity()));
    }

    public function testFindAclsWithDifferentTypes()
    {
        $oids = [];
        $oids[] = new ObjectIdentity('123', 'Bundle\SomeVendor\MyBundle\Entity\SomeEntity');
        $oids[] = new ObjectIdentity('123', 'Bundle\MyBundle\Entity\AnotherEntity');

        $provider = $this->getProvider();

        $acls = $provider->findAcls($oids);
        $this->assertInstanceOf('SplObjectStorage', $acls);
        $this->assertCount(2, $acls);
        $this->assertInstanceOf(Acl::class, $acl0 = $acls->offsetGet($oids[0]));
        $this->assertInstanceOf(Acl::class, $acl1 = $acls->offsetGet($oids[1]));
        $this->assertTrue($oids[0]->equals($acl0->getObjectIdentity()));
        $this->assertTrue($oids[1]->equals($acl1->getObjectIdentity()));
    }

    public function testFindAclCachesAclInMemory()
    {
        $oid = new ObjectIdentity('1', 'foo');
        $provider = $this->getProvider();

        $acl = $provider->findAcl($oid);
        $this->assertSame($acl, $cAcl = $provider->findAcl($oid));

        $cAces = $cAcl->getObjectAces();
        foreach ($acl->getObjectAces() as $index => $ace) {
            $this->assertSame($ace, $cAces[$index]);
        }
    }

    public function testFindAcl()
    {
        $oid = new ObjectIdentity('1', 'foo');
        $provider = $this->getProvider();

        $acl = $provider->findAcl($oid);

        $this->assertInstanceOf(Acl::class, $acl);
        $this->assertTrue($oid->equals($acl->getObjectIdentity()));
        $this->assertEquals(4, $acl->getId());
        $this->assertCount(0, $acl->getClassAces());
        $this->assertCount(0, $this->getField($acl, 'classFieldAces'));
        $this->assertCount(3, $acl->getObjectAces());
        $this->assertCount(0, $this->getField($acl, 'objectFieldAces'));

        $aces = $acl->getObjectAces();
        $this->assertInstanceOf(Entry::class, $aces[0]);
        $this->assertTrue($aces[0]->isGranting());
        $this->assertTrue($aces[0]->isAuditSuccess());
        $this->assertTrue($aces[0]->isAuditFailure());
        $this->assertEquals('all', $aces[0]->getStrategy());
        $this->assertSame(2, $aces[0]->getMask());

        // check ACE are in correct order
        $i = 0;
        foreach ($aces as $index => $ace) {
            $this->assertEquals($i, $index);
            ++$i;
        }

        $sid = $aces[0]->getSecurityIdentity();
        $this->assertInstanceOf(UserSecurityIdentity::class, $sid);
        $this->assertEquals('john.doe', $sid->getUsername());
        $this->assertEquals('SomeClass', $sid->getClass());
    }

    protected function setUp(): void
    {
        $configuration = new Configuration();

        /**
         * @psalm-suppress RedundantCondition Since we are compatibles with DBAL 2 and 3, we need to check if the method exists
         */
        if (method_exists($configuration, 'setSchemaManagerFactory')) {
            $configuration->setSchemaManagerFactory(new DefaultSchemaManagerFactory());
        }

        $this->connection = DriverManager::getConnection(
            [
                'driver' => 'pdo_sqlite',
                'memory' => true,
            ],
            $configuration
        );

        // import the schema
        $schema = new Schema($this->getOptions());
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->executeStatement($sql);
        }

        // populate the schema with some test data
        $insertClassStmt = $this->connection->prepare('INSERT INTO acl_classes (id, class_type) VALUES (?, ?)');
        foreach ($this->getClassData() as $data) {
            $insertClassStmt->bindValue(1, $data[0]);
            $insertClassStmt->bindValue(2, $data[1]);
            $insertClassStmt->executeStatement();
        }

        $insertSidStmt = $this->connection->prepare('INSERT INTO acl_security_identities (id, identifier, username) VALUES (?, ?, ?)');
        foreach ($this->getSidData() as $data) {
            $insertSidStmt->bindValue(1, $data[0]);
            $insertSidStmt->bindValue(2, $data[1]);
            $insertSidStmt->bindValue(3, $data[2]);
            $insertSidStmt->executeStatement();
        }

        $insertOidStmt = $this->connection->prepare('INSERT INTO acl_object_identities (id, class_id, object_identifier, parent_object_identity_id, entries_inheriting) VALUES (?, ?, ?, ?, ?)');
        foreach ($this->getOidData() as $data) {
            $insertOidStmt->bindValue(1, $data[0]);
            $insertOidStmt->bindValue(2, $data[1]);
            $insertOidStmt->bindValue(3, $data[2]);
            $insertOidStmt->bindValue(4, $data[3]);
            $insertOidStmt->bindValue(5, $data[4]);
            $insertOidStmt->executeStatement();
        }

        $insertEntryStmt = $this->connection->prepare('INSERT INTO acl_entries (id, class_id, object_identity_id, field_name, ace_order, security_identity_id, mask, granting, granting_strategy, audit_success, audit_failure) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        foreach ($this->getEntryData() as $data) {
            $insertEntryStmt->bindValue(1, $data[0]);
            $insertEntryStmt->bindValue(2, $data[1]);
            $insertEntryStmt->bindValue(3, $data[2]);
            $insertEntryStmt->bindValue(4, $data[3]);
            $insertEntryStmt->bindValue(5, $data[4]);
            $insertEntryStmt->bindValue(6, $data[5]);
            $insertEntryStmt->bindValue(7, $data[6]);
            $insertEntryStmt->bindValue(8, $data[7]);
            $insertEntryStmt->bindValue(9, $data[8]);
            $insertEntryStmt->bindValue(10, $data[9]);
            $insertEntryStmt->bindValue(11, $data[10]);
            $insertEntryStmt->executeStatement();
        }

        $insertOidAncestorStmt = $this->connection->prepare('INSERT INTO acl_object_identity_ancestors (object_identity_id, ancestor_id) VALUES (?, ?)');
        foreach ($this->getOidAncestorData() as $data) {
            $insertOidAncestorStmt->bindValue(1, $data[0]);
            $insertOidAncestorStmt->bindValue(2, $data[1]);
            $insertOidAncestorStmt->executeStatement();
        }
    }

    protected function tearDown(): void
    {
        $this->connection = null;
    }

    protected function getField($object, $field)
    {
        $reflection = new \ReflectionProperty($object, $field);
        $reflection->setAccessible(true);

        return $reflection->getValue($object);
    }

    protected function getEntryData()
    {
        // id, cid, oid, field, order, sid, mask, granting, strategy, a success, a failure
        return [
            [1, 1, 1, null, 0, 1, 1, 1, 'all', 1, 1],
            [2, 1, 1, null, 1, 2, 1 << 2 | 1 << 1, 0, 'any', 0, 0],
            [3, 3, 4, null, 0, 1, 2, 1, 'all', 1, 1],
            [4, 3, 4, null, 2, 2, 1, 1, 'all', 1, 1],
            [5, 3, 4, null, 1, 3, 1, 1, 'all', 1, 1],
        ];
    }

    protected function getOidData()
    {
        // id, cid, oid, parent_oid, entries_inheriting
        return [
            [1, 1, '123', null, 1],
            [2, 2, '123', 1, 1],
            [3, 2, 'i:3:123', 1, 1],
            [4, 3, '1', 2, 1],
            [5, 3, '2', 2, 1],
        ];
    }

    protected function getOidAncestorData()
    {
        return [
            [1, 1],
            [2, 1],
            [2, 2],
            [3, 1],
            [3, 3],
            [4, 2],
            [4, 1],
            [4, 4],
            [5, 2],
            [5, 1],
            [5, 5],
        ];
    }

    protected function getSidData()
    {
        return [
            [1, 'SomeClass-john.doe', 1],
            [2, 'MyClass-john.doe@foo.com', 1],
            [3, 'FooClass-123', 1],
            [4, 'MooClass-ROLE_USER', 1],
            [5, 'ROLE_USER', 0],
            [6, 'IS_AUTHENTICATED_FULLY', 0],
        ];
    }

    protected function getClassData()
    {
        return [
            [1, 'Bundle\SomeVendor\MyBundle\Entity\SomeEntity'],
            [2, 'Bundle\MyBundle\Entity\AnotherEntity'],
            [3, 'foo'],
        ];
    }

    protected function getOptions()
    {
        return [
            'oid_table_name' => 'acl_object_identities',
            'oid_ancestors_table_name' => 'acl_object_identity_ancestors',
            'class_table_name' => 'acl_classes',
            'sid_table_name' => 'acl_security_identities',
            'entry_table_name' => 'acl_entries',
        ];
    }

    protected function getStrategy(): PermissionGrantingStrategy
    {
        return new PermissionGrantingStrategy();
    }

    protected function getProvider(): AclProvider
    {
        return new AclProvider($this->connection, $this->getStrategy(), $this->getOptions());
    }
}
