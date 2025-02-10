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
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\DefaultSchemaManagerFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Acl\Dbal\AclProvider;
use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Dbal\Schema;
use Symfony\Component\Security\Acl\Domain\Acl;
use Symfony\Component\Security\Acl\Domain\Entry;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Exception\ConcurrentModificationException;
use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Symfony\Component\Security\Acl\Model\EntryInterface;
use Symfony\Component\Security\Acl\Model\FieldEntryInterface;

/**
 * @requires extension pdo_sqlite
 */
class MutableAclProviderTest extends TestCase
{
    protected $connection;

    public static function assertAceEquals(EntryInterface $a, EntryInterface $b)
    {
        self::assertInstanceOf($a::class, $b);

        foreach (['getId', 'getMask', 'getStrategy', 'isGranting'] as $getter) {
            self::assertSame($a->$getter(), $b->$getter());
        }

        self::assertTrue($a->getSecurityIdentity()->equals($b->getSecurityIdentity()));
        self::assertSame($a->getAcl()->getId(), $b->getAcl()->getId());

        if ($a instanceof AuditableEntryInterface) {
            self::assertSame($a->isAuditSuccess(), $b->isAuditSuccess());
            self::assertSame($a->isAuditFailure(), $b->isAuditFailure());
        }

        if ($a instanceof FieldEntryInterface) {
            self::assertSame($a->getField(), $b->getField());
        }
    }

    public function testCreateAclThrowsExceptionWhenAclAlreadyExists()
    {
        $this->expectException(\Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException::class);

        $provider = $this->getProvider();
        $oid = new ObjectIdentity('123456', 'FOO');
        $provider->createAcl($oid);
        $provider->createAcl($oid);
    }

    public function testCreateAcl()
    {
        $provider = $this->getProvider();
        $oid = new ObjectIdentity('123456', 'FOO');
        $acl = $provider->createAcl($oid);
        $cachedAcl = $provider->findAcl($oid);

        $this->assertInstanceOf(Acl::class, $acl);
        $this->assertSame($acl, $cachedAcl);
        $this->assertTrue($acl->getObjectIdentity()->equals($oid));
    }

    public function testDeleteAcl()
    {
        $provider = $this->getProvider();
        $oid = new ObjectIdentity(1, 'Foo');
        $acl = $provider->createAcl($oid);

        $provider->deleteAcl($oid);
        $loadedAcls = $this->getField($provider, 'loadedAcls');
        $this->assertCount(0, $loadedAcls['Foo']);

        try {
            $provider->findAcl($oid);
            $this->fail('ACL has not been properly deleted.');
        } catch (AclNotFoundException $e) {
        }
    }

    public function testDeleteAclDeletesChildren()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $parentAcl = $provider->createAcl(new ObjectIdentity(2, 'Foo'));
        $acl->setParentAcl($parentAcl);
        $provider->updateAcl($acl);
        $provider->deleteAcl($parentAcl->getObjectIdentity());

        $this->expectException(AclNotFoundException::class);
        $this->expectExceptionMessage('There is no ACL for the given object identity.');

        $provider->findAcl(new ObjectIdentity(1, 'Foo'));
    }

    public function testFindAclsAddsPropertyListener()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));

        $propertyChanges = $this->getField($provider, 'propertyChanges');
        $this->assertCount(1, $propertyChanges);
        $this->assertTrue($propertyChanges->contains($acl));
        $this->assertEquals([], $propertyChanges->offsetGet($acl));

        $listeners = $this->getField($acl, 'listeners');
        $this->assertSame($provider, $listeners[0]);
    }

    public function testFindAclsAddsPropertyListenerOnlyOnce()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $acl = $provider->findAcl(new ObjectIdentity(1, 'Foo'));

        $propertyChanges = $this->getField($provider, 'propertyChanges');
        $this->assertCount(1, $propertyChanges);
        $this->assertTrue($propertyChanges->contains($acl));
        $this->assertEquals([], $propertyChanges->offsetGet($acl));

        $listeners = $this->getField($acl, 'listeners');
        $this->assertCount(1, $listeners);
        $this->assertSame($provider, $listeners[0]);
    }

    public function testFindAclsAddsPropertyListenerToParentAcls()
    {
        $provider = $this->getProvider();
        $this->importAcls($provider, [
            'main' => [
                'object_identifier' => '1',
                'class_type' => 'foo',
                'parent_acl' => 'parent',
            ],
            'parent' => [
                'object_identifier' => '1',
                'class_type' => 'anotherFoo',
            ],
        ]);

        $propertyChanges = $this->getField($provider, 'propertyChanges');
        $this->assertCount(0, $propertyChanges);

        $acl = $provider->findAcl(new ObjectIdentity('1', 'foo'));
        $this->assertCount(2, $propertyChanges);
        $this->assertTrue($propertyChanges->contains($acl));
        $this->assertTrue($propertyChanges->contains($acl->getParentAcl()));
    }

    public function testPropertyChangedDoesNotTrackUnmanagedAcls()
    {
        $this->expectException(\InvalidArgumentException::class);

        $provider = $this->getProvider();
        $acl = new Acl(1, new ObjectIdentity(1, 'foo'), new PermissionGrantingStrategy(), [], false);

        $provider->propertyChanged($acl, 'classAces', [], ['foo']);
    }

    public function testPropertyChangedTracksChangesToAclProperties()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $propertyChanges = $this->getField($provider, 'propertyChanges');

        $provider->propertyChanged($acl, 'entriesInheriting', false, true);
        $changes = $propertyChanges->offsetGet($acl);
        $this->assertTrue(isset($changes['entriesInheriting']));
        $this->assertFalse($changes['entriesInheriting'][0]);
        $this->assertTrue($changes['entriesInheriting'][1]);

        $provider->propertyChanged($acl, 'entriesInheriting', true, false);
        $provider->propertyChanged($acl, 'entriesInheriting', false, true);
        $provider->propertyChanged($acl, 'entriesInheriting', true, false);
        $changes = $propertyChanges->offsetGet($acl);
        $this->assertFalse(isset($changes['entriesInheriting']));
    }

    public function testPropertyChangedTracksChangesToAceProperties()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $ace = new Entry(1, $acl, new UserSecurityIdentity('foo', 'FooClass'), 'all', 1, true, true, true);
        $ace2 = new Entry(2, $acl, new UserSecurityIdentity('foo', 'FooClass'), 'all', 1, true, true, true);
        $propertyChanges = $this->getField($provider, 'propertyChanges');

        $provider->propertyChanged($ace, 'mask', 1, 3);
        $changes = $propertyChanges->offsetGet($acl);
        $this->assertTrue(isset($changes['aces']));
        $this->assertInstanceOf('\SplObjectStorage', $changes['aces']);
        $this->assertTrue($changes['aces']->contains($ace));
        $aceChanges = $changes['aces']->offsetGet($ace);
        $this->assertTrue(isset($aceChanges['mask']));
        $this->assertEquals(1, $aceChanges['mask'][0]);
        $this->assertEquals(3, $aceChanges['mask'][1]);

        $provider->propertyChanged($ace, 'strategy', 'all', 'any');
        $changes = $propertyChanges->offsetGet($acl);
        $this->assertTrue(isset($changes['aces']));
        $this->assertInstanceOf('\SplObjectStorage', $changes['aces']);
        $this->assertTrue($changes['aces']->contains($ace));
        $aceChanges = $changes['aces']->offsetGet($ace);
        $this->assertTrue(isset($aceChanges['mask']));
        $this->assertTrue(isset($aceChanges['strategy']));
        $this->assertEquals('all', $aceChanges['strategy'][0]);
        $this->assertEquals('any', $aceChanges['strategy'][1]);

        $provider->propertyChanged($ace, 'mask', 3, 1);
        $changes = $propertyChanges->offsetGet($acl);
        $aceChanges = $changes['aces']->offsetGet($ace);
        $this->assertFalse(isset($aceChanges['mask']));
        $this->assertTrue(isset($aceChanges['strategy']));

        $provider->propertyChanged($ace2, 'mask', 1, 3);
        $provider->propertyChanged($ace, 'strategy', 'any', 'all');
        $changes = $propertyChanges->offsetGet($acl);
        $this->assertTrue(isset($changes['aces']));
        $this->assertFalse($changes['aces']->contains($ace));
        $this->assertTrue($changes['aces']->contains($ace2));

        $provider->propertyChanged($ace2, 'mask', 3, 4);
        $provider->propertyChanged($ace2, 'mask', 4, 1);
        $changes = $propertyChanges->offsetGet($acl);
        $this->assertFalse(isset($changes['aces']));
    }

    public function testUpdateAclDoesNotAcceptUntrackedAcls()
    {
        $this->expectException(\InvalidArgumentException::class);

        $provider = $this->getProvider();
        $acl = new Acl(1, new ObjectIdentity(1, 'Foo'), new PermissionGrantingStrategy(), [], true);
        $provider->updateAcl($acl);
    }

    public function testUpdateDoesNothingWhenThereAreNoChanges()
    {
        $con = $this->createMock(Connection::class);

        $con
            ->expects($this->never())
            ->method('beginTransaction')
        ;
        $con
            ->expects($this->never())
            ->method('executeUpdate')
        ;

        $provider = new MutableAclProvider($con, new PermissionGrantingStrategy(), []);
        $acl = new Acl(1, new ObjectIdentity(1, 'Foo'), new PermissionGrantingStrategy(), [], true);
        $propertyChanges = $this->getField($provider, 'propertyChanges');
        $propertyChanges->offsetSet($acl, []);
        $provider->updateAcl($acl);
    }

    public function testUpdateAclThrowsExceptionOnConcurrentModificationOfSharedProperties()
    {
        $provider = $this->getProvider();
        $acl1 = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $acl2 = $provider->createAcl(new ObjectIdentity(2, 'Foo'));
        $acl3 = $provider->createAcl(new ObjectIdentity(1, 'AnotherFoo'));
        $sid = new RoleSecurityIdentity('ROLE_FOO');

        $acl1->insertClassAce($sid, 1);
        $acl3->insertClassAce($sid, 1);
        $provider->updateAcl($acl1);
        $provider->updateAcl($acl3);

        $acl2->insertClassAce($sid, 16);
        $provider->updateAcl($acl2);

        $acl1->insertClassAce($sid, 3);
        $acl2->insertClassAce($sid, 5);

        $this->expectException(ConcurrentModificationException::class);
        $this->expectExceptionMessage('The "classAces" property has been modified concurrently.');

        $provider->updateAcl($acl1);
    }

    public function testUpdateAcl()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $sid = new UserSecurityIdentity('johannes', 'FooClass');
        $acl->setEntriesInheriting(!$acl->isEntriesInheriting());

        $acl->insertObjectAce($sid, 1);
        $acl->insertClassAce($sid, 5, 0, false);
        $acl->insertObjectAce($sid, 2, 1, true);
        $acl->insertClassFieldAce('field', $sid, 2, 0, true);
        $provider->updateAcl($acl);

        $acl->updateObjectAce(0, 3);
        $acl->deleteObjectAce(1);
        $acl->updateObjectAuditing(0, true, false);
        $acl->updateClassFieldAce(0, 'field', 15);
        $provider->updateAcl($acl);

        $reloadProvider = $this->getProvider();
        $reloadedAcl = $reloadProvider->findAcl(new ObjectIdentity(1, 'Foo'));
        $this->assertNotSame($acl, $reloadedAcl);
        $this->assertSame($acl->isEntriesInheriting(), $reloadedAcl->isEntriesInheriting());

        $aces = $acl->getObjectAces();
        $reloadedAces = $reloadedAcl->getObjectAces();
        $this->assertEquals(\count($aces), \count($reloadedAces));
        foreach ($aces as $index => $ace) {
            $this->assertAceEquals($ace, $reloadedAces[$index]);
        }
    }

    public function testUpdateAclWorksForChangingTheParentAcl()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $parentAcl = $provider->createAcl(new ObjectIdentity(1, 'AnotherFoo'));
        $acl->setParentAcl($parentAcl);
        $provider->updateAcl($acl);

        $reloadProvider = $this->getProvider();
        $reloadedAcl = $reloadProvider->findAcl(new ObjectIdentity(1, 'Foo'));
        $this->assertNotSame($acl, $reloadedAcl);
        $this->assertSame($parentAcl->getId(), $reloadedAcl->getParentAcl()->getId());
    }

    public function testUpdateAclUpdatesChildAclsCorrectly()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));

        $parentAcl = $provider->createAcl(new ObjectIdentity(1, 'Bar'));
        $acl->setParentAcl($parentAcl);
        $provider->updateAcl($acl);

        $parentParentAcl = $provider->createAcl(new ObjectIdentity(1, 'Baz'));
        $parentAcl->setParentAcl($parentParentAcl);
        $provider->updateAcl($parentAcl);

        $newParentParentAcl = $provider->createAcl(new ObjectIdentity(2, 'Baz'));
        $parentAcl->setParentAcl($newParentParentAcl);
        $provider->updateAcl($parentAcl);

        $reloadProvider = $this->getProvider();
        $reloadedAcl = $reloadProvider->findAcl(new ObjectIdentity(1, 'Foo'));
        $this->assertEquals($newParentParentAcl->getId(), $reloadedAcl->getParentAcl()->getParentAcl()->getId());
    }

    public function testUpdateAclInsertingMultipleObjectFieldAcesThrowsDBConstraintViolations()
    {
        $provider = $this->getProvider();
        $oid = new ObjectIdentity(1, 'Foo');
        $sid1 = new UserSecurityIdentity('johannes', 'FooClass');
        $sid2 = new UserSecurityIdentity('guilro', 'FooClass');
        $sid3 = new UserSecurityIdentity('bmaz', 'FooClass');
        $fieldName = 'fieldName';

        $acl = $provider->createAcl($oid);
        $acl->insertObjectFieldAce($fieldName, $sid1, 4);
        $provider->updateAcl($acl);

        $acl = $provider->findAcl($oid);
        $acl->insertObjectFieldAce($fieldName, $sid2, 4);
        $provider->updateAcl($acl);

        $acl = $provider->findAcl($oid);
        $acl->insertObjectFieldAce($fieldName, $sid3, 4);
        $provider->updateAcl($acl);

        $acls = $provider->findAcl($oid);
        $this->assertCount(3, $acls->getObjectFieldAces($fieldName));
    }

    public function testUpdateAclDeletingObjectFieldAcesThrowsDBConstraintViolations()
    {
        $provider = $this->getProvider();
        $oid = new ObjectIdentity(1, 'Foo');
        $sid1 = new UserSecurityIdentity('johannes', 'FooClass');
        $sid2 = new UserSecurityIdentity('guilro', 'FooClass');
        $sid3 = new UserSecurityIdentity('bmaz', 'FooClass');
        $fieldName = 'fieldName';

        $acl = $provider->createAcl($oid);
        $acl->insertObjectFieldAce($fieldName, $sid1, 4);
        $provider->updateAcl($acl);

        $acl = $provider->findAcl($oid);
        $acl->insertObjectFieldAce($fieldName, $sid2, 4);
        $provider->updateAcl($acl);

        $index = 0;
        $acl->deleteObjectFieldAce($index, $fieldName);
        $provider->updateAcl($acl);

        $acl = $provider->findAcl($oid);
        $acl->insertObjectFieldAce($fieldName, $sid3, 4);
        $provider->updateAcl($acl);

        $acls = $provider->findAcl($oid);
        $this->assertCount(2, $acls->getObjectFieldAces($fieldName));
    }

    public function testUpdateUserSecurityIdentity()
    {
        $provider = $this->getProvider();
        $acl = $provider->createAcl(new ObjectIdentity(1, 'Foo'));
        $sid = new UserSecurityIdentity('johannes', 'FooClass');
        $acl->setEntriesInheriting(!$acl->isEntriesInheriting());

        $acl->insertObjectAce($sid, 1);
        $acl->insertClassAce($sid, 5, 0, false);
        $acl->insertObjectAce($sid, 2, 1, true);
        $acl->insertClassFieldAce('field', $sid, 2, 0, true);
        $provider->updateAcl($acl);

        $newSid = new UserSecurityIdentity('mathieu', 'FooClass');
        $provider->updateUserSecurityIdentity($newSid, 'johannes');

        $reloadProvider = $this->getProvider();
        $reloadedAcl = $reloadProvider->findAcl(new ObjectIdentity(1, 'Foo'));

        $this->assertNotSame($acl, $reloadedAcl);
        $this->assertSame($acl->isEntriesInheriting(), $reloadedAcl->isEntriesInheriting());

        $aces = $acl->getObjectAces();
        $reloadedAces = $reloadedAcl->getObjectAces();
        $this->assertEquals(\count($aces), \count($reloadedAces));
        foreach ($reloadedAces as $ace) {
            $this->assertTrue($ace->getSecurityIdentity()->equals($newSid));
        }
    }

    /**
     * Imports acls.
     *
     * Data must have the following format:
     * array(
     *     *name* => array(
     *         'object_identifier' => *required*
     *         'class_type' => *required*,
     *         'parent_acl' => *name (optional)*
     *     ),
     * )
     *
     * @throws \InvalidArgumentException
     * @throws \Exception
     */
    protected function importAcls(AclProvider $provider, array $data)
    {
        $aclIds = $parentAcls = [];
        $con = $this->getField($provider, 'connection');
        $con->beginTransaction();
        try {
            foreach ($data as $name => $aclData) {
                if (!isset($aclData['object_identifier'], $aclData['class_type'])) {
                    throw new \InvalidArgumentException('"object_identifier", and "class_type" must be present.');
                }

                $this->callMethod($provider, 'createObjectIdentity', [new ObjectIdentity($aclData['object_identifier'], $aclData['class_type'])]);
                $aclId = $con->lastInsertId();
                $aclIds[$name] = $aclId;

                $sql = $this->callMethod($provider, 'getInsertObjectIdentityRelationSql', [$aclId, $aclId]);
                $con->executeStatement($sql);

                if (isset($aclData['parent_acl'])) {
                    if (isset($aclIds[$aclData['parent_acl']])) {
                        $con->executeStatement('UPDATE acl_object_identities SET parent_object_identity_id = '.$aclIds[$aclData['parent_acl']].' WHERE id = '.$aclId);
                        $con->executeStatement($this->callMethod($provider, 'getInsertObjectIdentityRelationSql', [$aclId, $aclIds[$aclData['parent_acl']]]));
                    } else {
                        $parentAcls[$aclId] = $aclData['parent_acl'];
                    }
                }
            }

            foreach ($parentAcls as $aclId => $name) {
                if (!isset($aclIds[$name])) {
                    throw new \InvalidArgumentException(sprintf('"%s" does not exist.', $name));
                }

                $con->executeStatement(sprintf('UPDATE acl_object_identities SET parent_object_identity_id = %d WHERE id = %d', $aclIds[$name], $aclId));
                $con->executeStatement($this->callMethod($provider, 'getInsertObjectIdentityRelationSql', [$aclId, $aclIds[$name]]));
            }

            $con->commit();
        } catch (\Exception $e) {
            $con->rollBack();

            throw $e;
        }
    }

    protected function callMethod($object, $method, array $args)
    {
        $method = new \ReflectionMethod($object, $method);
        $method->setAccessible(true);

        return $method->invokeArgs($object, $args);
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
        $this->connection->setNestTransactionsWithSavepoints(true);

        // import the schema
        $schema = new Schema($this->getOptions());
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->executeStatement($sql);
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

    public function setField($object, $field, $value)
    {
        $reflection = new \ReflectionProperty($object, $field);
        $reflection->setAccessible(true);
        $reflection->setValue($object, $value);
        $reflection->setAccessible(false);
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

    protected function getStrategy()
    {
        return new PermissionGrantingStrategy();
    }

    protected function getProvider($cache = null)
    {
        return new MutableAclProvider($this->connection, $this->getStrategy(), $this->getOptions(), $cache);
    }
}
