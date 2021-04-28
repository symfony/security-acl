<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

require_once __DIR__.'/../../vendor/autoload.php';

use Symfony\Component\Finder\Finder;
use Symfony\Component\Security\Acl\Dbal\Schema;

$schema = new Schema([
    'class_table_name' => 'acl_classes',
    'entry_table_name' => 'acl_entries',
    'oid_table_name' => 'acl_object_identities',
    'oid_ancestors_table_name' => 'acl_object_identity_ancestors',
    'sid_table_name' => 'acl_security_identities',
]);

$reflection = new ReflectionClass('Doctrine\\DBAL\\Platforms\\AbstractPlatform');
$finder = new Finder();
$finder->name('*Platform.php')->in(dirname($reflection->getFileName()));
foreach ($finder as $file) {
    $className = 'Doctrine\\DBAL\\Platforms\\'.$file->getBasename('.php');

    $reflection = new ReflectionClass($className);
    if ($reflection->isAbstract()) {
        continue;
    }

    $platform = $reflection->newInstance();
    $targetFile = sprintf(__DIR__.'/../schema/%s.sql', $platform->getName());
    file_put_contents($targetFile, implode("\n\n", $schema->toSql($platform)));
}
