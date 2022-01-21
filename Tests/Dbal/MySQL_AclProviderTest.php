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
 * @requires extension pdo_mysql
 * @group integration
 * @group mysql
 */
class MySQL_AclProviderTest extends AclProviderTest
{
    /** @return Connection */
    protected function createConnection()
    {
        $connection = DriverManager::getConnection([
            'driver' => 'pdo_mysql',
            'host' => '127.0.0.1',
            'user' => 'root',
            'password' => 'root',
            'dbname' => 'acl_test',
        ]);

        return $connection;
    }
}
