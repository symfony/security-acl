<?php

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

/**
 * @requires extension oci8
 * @group integration
 * @group oracle
 */
class Oracle_AclProviderTest extends AclProviderTest
{
    /** @return Connection */
    protected function createConnection()
    {
        $connection = DriverManager::getConnection([
            'driver' => 'oci8',
            'host' => '127.0.0.1',
            'user' => 'oracle',
            'password' => 'oracle',
            'dbname' => 'XEPDB1',
            'service' => true,
        ]);

        return $connection;
    }

    public function testFindAclsWithDifferentTypes()
    {
        $this->markTestSkipped('TODO: This test fails using OCI8');
    }
}
