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

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Acl\Dbal\AclProvider;
use Symfony\Component\Security\Acl\Dbal\Schema;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;

/**
 * @group benchmark
 */
class AclProviderBenchmarkTest extends TestCase
{
    /** @var Connection */
    protected $connection;
    protected $insertClassStmt;
    protected $insertSidStmt;
    protected $insertOidAncestorStmt;
    protected $insertOidStmt;
    protected $insertEntryStmt;

    protected function setUp(): void
    {
        try {
            $this->connection = DriverManager::getConnection([
                'driver' => 'pdo_mysql',
                'host' => 'localhost',
                'user' => 'root',
                'dbname' => 'testdb',
            ]);
            $this->connection->connect();
        } catch (\Exception $e) {
            $this->markTestSkipped('Unable to connect to the database: '.$e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        $this->connection = null;
    }

    public function testFindAcls()
    {
        // $this->generateTestData();

        // get some random test object identities from the database
        $oids = [];
        $stmt = $this->connection->executeQuery('SELECT object_identifier, class_type FROM acl_object_identities o INNER JOIN acl_classes c ON c.id = o.class_id ORDER BY RAND() LIMIT 25');
        foreach ($stmt->fetchAllAssociative() as $oid) {
            $oids[] = new ObjectIdentity($oid['object_identifier'], $oid['class_type']);
        }

        $provider = $this->getProvider();

        $start = microtime(true);
        $provider->findAcls($oids);
        $time = microtime(true) - $start;
        echo 'Total Time: '.$time."s\n";
    }

    /**
     * This generates a huge amount of test data to be used mainly for benchmarking
     * purposes, not so much for testing. That's why it's not called by default.
     */
    protected function generateTestData()
    {
        $sm = $this->connection->createSchemaManager();
        $sm->dropDatabase('testdb');
        $sm->createDatabase('testdb');
        $this->connection->executeStatement('USE testdb');

        // import the schema
        $schema = new Schema($options = $this->getOptions());
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->executeStatement($sql);
        }

        // setup prepared statements
        $this->insertClassStmt = $this->connection->prepare('INSERT INTO acl_classes (id, class_type) VALUES (?, ?)');
        $this->insertSidStmt = $this->connection->prepare('INSERT INTO acl_security_identities (id, identifier, username) VALUES (?, ?, ?)');
        $this->insertOidStmt = $this->connection->prepare('INSERT INTO acl_object_identities (id, class_id, object_identifier, parent_object_identity_id, entries_inheriting) VALUES (?, ?, ?, ?, ?)');
        $this->insertEntryStmt = $this->connection->prepare('INSERT INTO acl_entries (id, class_id, object_identity_id, field_name, ace_order, security_identity_id, mask, granting, granting_strategy, audit_success, audit_failure) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $this->insertOidAncestorStmt = $this->connection->prepare('INSERT INTO acl_object_identity_ancestors (object_identity_id, ancestor_id) VALUES (?, ?)');

        for ($i = 0; $i < 40000; ++$i) {
            $this->generateAclHierarchy();
        }
    }

    protected function generateAclHierarchy()
    {
        $rootId = $this->generateAcl($this->chooseClassId(), null, []);

        $this->generateAclLevel(rand(1, 15), $rootId, [$rootId]);
    }

    protected function generateAclLevel($depth, $parentId, $ancestors)
    {
        $level = \count($ancestors);
        for ($i = 0, $t = rand(1, 10); $i < $t; ++$i) {
            $id = $this->generateAcl($this->chooseClassId(), $parentId, $ancestors);

            if ($level < $depth) {
                $this->generateAclLevel($depth, $id, array_merge($ancestors, [$id]));
            }
        }
    }

    protected function chooseClassId()
    {
        static $id = 1000;

        if (1000 === $id || ($id < 1500 && rand(0, 1))) {
            $this->insertClassStmt->executeStatement([$id, $this->getRandomString(rand(20, 100), 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\_')]);
            ++$id;

            return $id - 1;
        } else {
            return rand(1000, $id - 1);
        }
    }

    protected function generateAcl($classId, $parentId, $ancestors)
    {
        static $id = 1000;

        $this->insertOidStmt->executeStatement([
            $id,
            $classId,
            $this->getRandomString(rand(20, 50)),
            $parentId,
            rand(0, 1),
        ]);

        $this->insertOidAncestorStmt->executeStatement([$id, $id]);
        foreach ($ancestors as $ancestor) {
            $this->insertOidAncestorStmt->executeStatement([$id, $ancestor]);
        }

        $this->generateAces($classId, $id);
        ++$id;

        return $id - 1;
    }

    protected function chooseSid()
    {
        static $id = 1000;

        if (1000 === $id || ($id < 11000 && rand(0, 1))) {
            $this->insertSidStmt->executeStatement([
                $id,
                $this->getRandomString(rand(5, 30)),
                rand(0, 1),
            ]);
            ++$id;

            return $id - 1;
        } else {
            return rand(1000, $id - 1);
        }
    }

    protected function generateAces($classId, $objectId)
    {
        static $id = 1000;

        $sids = [];
        $fieldOrder = [];

        for ($i = 0; $i <= 30; ++$i) {
            $fieldName = rand(0, 1) ? null : $this->getRandomString(rand(10, 20));

            do {
                $sid = $this->chooseSid();
            } while (\array_key_exists($sid, $sids) && \in_array($fieldName, $sids[$sid], true));

            $fieldOrder[$fieldName] = \array_key_exists($fieldName, $fieldOrder) ? $fieldOrder[$fieldName] + 1 : 0;
            if (!isset($sids[$sid])) {
                $sids[$sid] = [];
            }
            $sids[$sid][] = $fieldName;

            $strategy = rand(0, 2);
            if (0 === $strategy) {
                $strategy = PermissionGrantingStrategy::ALL;
            } elseif (1 === $strategy) {
                $strategy = PermissionGrantingStrategy::ANY;
            } else {
                $strategy = PermissionGrantingStrategy::EQUAL;
            }

            // id, cid, oid, field, order, sid, mask, granting, strategy, a success, a failure
            $this->insertEntryStmt->executeStatement([
                $id,
                $classId,
                rand(0, 5) ? $objectId : null,
                $fieldName,
                $fieldOrder[$fieldName],
                $sid,
                $this->generateMask(),
                rand(0, 1),
                $strategy,
                rand(0, 1),
                rand(0, 1),
            ]);

            ++$id;
        }
    }

    protected function generateMask()
    {
        $i = rand(1, 30);
        $mask = 0;

        while ($i <= 30) {
            $mask |= 1 << rand(0, 30);
            ++$i;
        }

        return $mask;
    }

    protected function getRandomString($length, $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    {
        $s = '';
        $cLength = \strlen($chars);

        while (\strlen($s) < $length) {
            $s .= $chars[mt_rand(0, $cLength - 1)];
        }

        return $s;
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

    protected function getProvider()
    {
        return new AclProvider($this->connection, $this->getStrategy(), $this->getOptions());
    }
}
