<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Acl\Dbal;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\SQLServerPlatform;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\ForeignKeyConstraint;
use Doctrine\DBAL\Schema\ForeignKeyConstraint\ReferentialAction;
use Doctrine\DBAL\Schema\Index;
use Doctrine\DBAL\Schema\Index\IndexType;
use Doctrine\DBAL\Schema\PrimaryKeyConstraint;
use Doctrine\DBAL\Schema\Schema as BaseSchema;
use Doctrine\DBAL\Schema\SchemaConfig;
use Doctrine\DBAL\Schema\Table;

/**
 * The schema used for the ACL system.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
final class Schema extends BaseSchema
{
    protected $options;
    protected $platform;

    /**
     * @param array $options the names for tables
     */
    public function __construct(array $options, ?Connection $connection = null)
    {
        $schemaConfig = $this->createSchemaConfig($connection);

        $this->options = $options;
        $this->platform = $connection ? $connection->getDatabasePlatform() : null;

        if (method_exists(BaseSchema::class, 'edit')) {
            parent::__construct($this->createTables($schemaConfig ?? new SchemaConfig()), [], $schemaConfig);

            return;
        }

        parent::__construct([], [], $schemaConfig);

        $this->addClassTable();
        $this->addSecurityIdentitiesTable();
        $this->addObjectIdentitiesTable();
        $this->addObjectIdentityAncestorsTable();
        $this->addEntryTable();
    }

    /**
     * Merges ACL schema with the given schema.
     */
    public function addToSchema(BaseSchema $schema)
    {
        foreach ($this->getTables() as $table) {
            $schema->_addTable($table);
        }

        foreach ($this->getSequences() as $sequence) {
            $schema->_addSequence($sequence);
        }
    }

    /**
     * Adds the class table to the schema.
     */
    protected function addClassTable()
    {
        $table = $this->createTable($this->options['class_table_name']);
        $table->addColumn('id', 'integer', ['unsigned' => true, 'autoincrement' => true]);
        $table->addColumn('class_type', 'string', ['length' => 200]);
        $this->setPrimaryKey($table, ['id']);
        $table->addUniqueIndex(['class_type']);
    }

    /**
     * Adds the entry table to the schema.
     */
    protected function addEntryTable()
    {
        $table = $this->createTable($this->options['entry_table_name']);

        $table->addColumn('id', 'integer', ['unsigned' => true, 'autoincrement' => true]);
        $table->addColumn('class_id', 'integer', ['unsigned' => true]);
        $table->addColumn('object_identity_id', 'integer', ['unsigned' => true, 'notnull' => false]);
        $table->addColumn('field_name', 'string', ['length' => 50, 'notnull' => false]);
        $table->addColumn('ace_order', 'smallint', ['unsigned' => true]);
        $table->addColumn('security_identity_id', 'integer', ['unsigned' => true]);
        $table->addColumn('mask', 'integer');
        $table->addColumn('granting', 'boolean');
        $table->addColumn('granting_strategy', 'string', ['length' => 30]);
        $table->addColumn('audit_success', 'boolean');
        $table->addColumn('audit_failure', 'boolean');

        $this->setPrimaryKey($table, ['id']);
        $table->addUniqueIndex(['class_id', 'object_identity_id', 'field_name', 'ace_order']);
        $table->addIndex(['class_id', 'object_identity_id', 'security_identity_id']);

        $table->addForeignKeyConstraint($this->options['class_table_name'], ['class_id'], ['id'], ['onDelete' => 'CASCADE', 'onUpdate' => 'CASCADE']);
        $table->addForeignKeyConstraint($this->options['oid_table_name'], ['object_identity_id'], ['id'], ['onDelete' => 'CASCADE', 'onUpdate' => 'CASCADE']);
        $table->addForeignKeyConstraint($this->options['sid_table_name'], ['security_identity_id'], ['id'], ['onDelete' => 'CASCADE', 'onUpdate' => 'CASCADE']);
    }

    /**
     * Adds the object identity table to the schema.
     */
    protected function addObjectIdentitiesTable()
    {
        $table = $this->createTable($this->options['oid_table_name']);

        $table->addColumn('id', 'integer', ['unsigned' => true, 'autoincrement' => true]);
        $table->addColumn('class_id', 'integer', ['unsigned' => true]);
        $table->addColumn('object_identifier', 'string', ['length' => 100]);
        $table->addColumn('parent_object_identity_id', 'integer', ['unsigned' => true, 'notnull' => false]);
        $table->addColumn('entries_inheriting', 'boolean');

        $this->setPrimaryKey($table, ['id']);
        $table->addUniqueIndex(['object_identifier', 'class_id']);
        $table->addIndex(['parent_object_identity_id']);

        $table->addForeignKeyConstraint($this->options['oid_table_name'], ['parent_object_identity_id'], ['id']);
    }

    /**
     * Adds the object identity relation table to the schema.
     */
    protected function addObjectIdentityAncestorsTable()
    {
        $table = $this->createTable($this->options['oid_ancestors_table_name']);

        $table->addColumn('object_identity_id', 'integer', ['unsigned' => true]);
        $table->addColumn('ancestor_id', 'integer', ['unsigned' => true]);

        $this->setPrimaryKey($table, ['object_identity_id', 'ancestor_id']);

        $action = 'CASCADE';
        if ($this->platform instanceof SQLServerPlatform) {
            // MS SQL Server does not support recursive cascading
            $action = 'NO ACTION';
        }
        $table->addForeignKeyConstraint($this->options['oid_table_name'], ['object_identity_id'], ['id'], ['onDelete' => $action, 'onUpdate' => $action]);
        $table->addForeignKeyConstraint($this->options['oid_table_name'], ['ancestor_id'], ['id'], ['onDelete' => $action, 'onUpdate' => $action]);
    }

    /**
     * Adds the security identity table to the schema.
     */
    protected function addSecurityIdentitiesTable()
    {
        $table = $this->createTable($this->options['sid_table_name']);

        $table->addColumn('id', 'integer', ['unsigned' => true, 'autoincrement' => true]);
        $table->addColumn('identifier', 'string', ['length' => 200]);
        $table->addColumn('username', 'boolean');

        $this->setPrimaryKey($table, ['id']);
        $table->addUniqueIndex(['identifier', 'username']);
    }

    private function setPrimaryKey(Table $table, array $columnNames): void
    {
        if (class_exists(PrimaryKeyConstraint::class)) {
            $table->addPrimaryKeyConstraint(PrimaryKeyConstraint::editor()->setUnquotedColumnNames(...$columnNames)->create());
        } else {
            $table->setPrimaryKey($columnNames);
        }
    }

    /**
     * @return Table[]
     */
    private function createTables(SchemaConfig $schemaConfig): array
    {
        $tableConfiguration = $schemaConfig->toTableConfiguration();
        $tableOptions = $schemaConfig->getDefaultTableOptions();
        $maxIdentifierLength = $tableConfiguration->getMaxIdentifierLength();

        // Generates the same names as Table::addIndex() and Table::addForeignKeyConstraint() so that existing schemas don't change
        $name = static function (string $prefix, string ...$parts) use ($maxIdentifierLength): string {
            return strtoupper(substr($prefix.'_'.implode('', array_map('dechex', array_map('crc32', $parts))), 0, $maxIdentifierLength));
        };
        $index = static function (string $table, bool $unique, string ...$columns) use ($name): Index {
            $editor = Index::editor()->setUnquotedName($name($unique ? 'uniq' : 'idx', $table, ...$columns));

            if ($unique) {
                $editor->setType(IndexType::UNIQUE);
            }
            foreach ($columns as $column) {
                $editor->addUnquotedColumnName($column);
            }

            return $editor->create();
        };
        $foreignKey = static function (string $table, string $column, string $foreignTable, ?ReferentialAction $action = null) use ($name): ForeignKeyConstraint {
            $editor = ForeignKeyConstraint::editor()
                ->setUnquotedName($name('fk', $table, $column))
                ->setUnquotedReferencingColumnNames($column)
                ->setUnquotedReferencedTableName($foreignTable)
                ->setUnquotedReferencedColumnNames('id');

            if (null !== $action) {
                $editor->setOnDeleteAction($action)->setOnUpdateAction($action);
            }

            return $editor->create();
        };
        $column = static function (string $name, string $type, array $options = []): Column {
            return Column::editor()
                ->setUnquotedName($name)
                ->setTypeName($type)
                ->setUnsigned($options['unsigned'] ?? false)
                ->setAutoincrement($options['autoincrement'] ?? false)
                ->setNotNull($options['notnull'] ?? true)
                ->setLength($options['length'] ?? null)
                ->create();
        };
        $table = static function (string $name, array $columns, array $primaryKey, array $indexes = [], array $foreignKeys = []) use ($tableOptions, $tableConfiguration): Table {
            $editor = Table::editor()
                ->setUnquotedName($name)
                ->setColumns(...$columns)
                ->setPrimaryKeyConstraint(PrimaryKeyConstraint::editor()->setUnquotedColumnNames(...$primaryKey)->create())
                ->setOptions($tableOptions)
                ->setConfiguration($tableConfiguration);

            foreach ($indexes as $index) {
                $editor->addIndex($index);
            }
            foreach ($foreignKeys as $foreignKey) {
                $editor->addForeignKeyConstraint($foreignKey);
            }

            return $editor->create();
        };

        $classTable = $this->options['class_table_name'];
        $sidTable = $this->options['sid_table_name'];
        $oidTable = $this->options['oid_table_name'];
        $oidAncestorsTable = $this->options['oid_ancestors_table_name'];
        $entryTable = $this->options['entry_table_name'];
        $id = $column('id', 'integer', ['unsigned' => true, 'autoincrement' => true]);
        // MS SQL Server does not support recursive cascading
        $ancestorsAction = $this->platform instanceof SQLServerPlatform ? ReferentialAction::NO_ACTION : ReferentialAction::CASCADE;

        return [
            $table($classTable, [
                $id,
                $column('class_type', 'string', ['length' => 200]),
            ], ['id'], [
                $index($classTable, true, 'class_type'),
            ]),
            $table($sidTable, [
                $id,
                $column('identifier', 'string', ['length' => 200]),
                $column('username', 'boolean'),
            ], ['id'], [
                $index($sidTable, true, 'identifier', 'username'),
            ]),
            $table($oidTable, [
                $id,
                $column('class_id', 'integer', ['unsigned' => true]),
                $column('object_identifier', 'string', ['length' => 100]),
                $column('parent_object_identity_id', 'integer', ['unsigned' => true, 'notnull' => false]),
                $column('entries_inheriting', 'boolean'),
            ], ['id'], [
                $index($oidTable, true, 'object_identifier', 'class_id'),
                $index($oidTable, false, 'parent_object_identity_id'),
            ], [
                $foreignKey($oidTable, 'parent_object_identity_id', $oidTable),
            ]),
            $table($oidAncestorsTable, [
                $column('object_identity_id', 'integer', ['unsigned' => true]),
                $column('ancestor_id', 'integer', ['unsigned' => true]),
            ], ['object_identity_id', 'ancestor_id'], [], [
                $foreignKey($oidAncestorsTable, 'object_identity_id', $oidTable, $ancestorsAction),
                $foreignKey($oidAncestorsTable, 'ancestor_id', $oidTable, $ancestorsAction),
            ]),
            $table($entryTable, [
                $id,
                $column('class_id', 'integer', ['unsigned' => true]),
                $column('object_identity_id', 'integer', ['unsigned' => true, 'notnull' => false]),
                $column('field_name', 'string', ['length' => 50, 'notnull' => false]),
                $column('ace_order', 'smallint', ['unsigned' => true]),
                $column('security_identity_id', 'integer', ['unsigned' => true]),
                $column('mask', 'integer'),
                $column('granting', 'boolean'),
                $column('granting_strategy', 'string', ['length' => 30]),
                $column('audit_success', 'boolean'),
                $column('audit_failure', 'boolean'),
            ], ['id'], [
                $index($entryTable, true, 'class_id', 'object_identity_id', 'field_name', 'ace_order'),
                $index($entryTable, false, 'class_id', 'object_identity_id', 'security_identity_id'),
            ], [
                $foreignKey($entryTable, 'class_id', $classTable, ReferentialAction::CASCADE),
                $foreignKey($entryTable, 'object_identity_id', $oidTable, ReferentialAction::CASCADE),
                $foreignKey($entryTable, 'security_identity_id', $sidTable, ReferentialAction::CASCADE),
            ]),
        ];
    }

    private function createSchemaConfig(?Connection $connection): ?SchemaConfig
    {
        if (null === $connection) {
            return null;
        }

        $schemaManager = method_exists($connection, 'createSchemaManager')
            ? $connection->createSchemaManager()
            : $connection->getSchemaManager()
        ;

        return $schemaManager->createSchemaConfig();
    }
}
