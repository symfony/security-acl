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

namespace Symfony\Component\Security\Acl\Permission;

/**
 * This is basic permission map complements the masks which have been defined
 * on the standard implementation of the MaskBuilder.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class BasicPermissionMap implements PermissionMapInterface, MaskBuilderRetrievalInterface
{
    public const PERMISSION_VIEW = 'VIEW';
    public const PERMISSION_EDIT = 'EDIT';
    public const PERMISSION_CREATE = 'CREATE';
    public const PERMISSION_DELETE = 'DELETE';
    public const PERMISSION_UNDELETE = 'UNDELETE';
    public const PERMISSION_OPERATOR = 'OPERATOR';
    public const PERMISSION_MASTER = 'MASTER';
    public const PERMISSION_OWNER = 'OWNER';

    /**
     * @var array<string,array<int,int>>
     */
    protected array $map;

    public function __construct()
    {
        $this->map = [
            self::PERMISSION_VIEW => [
                MaskBuilder::MASK_VIEW,
                MaskBuilder::MASK_EDIT,
                MaskBuilder::MASK_OPERATOR,
                MaskBuilder::MASK_MASTER,
                MaskBuilder::MASK_OWNER,
            ],

            self::PERMISSION_EDIT => [
                MaskBuilder::MASK_EDIT,
                MaskBuilder::MASK_OPERATOR,
                MaskBuilder::MASK_MASTER,
                MaskBuilder::MASK_OWNER,
            ],

            self::PERMISSION_CREATE => [
                MaskBuilder::MASK_CREATE,
                MaskBuilder::MASK_OPERATOR,
                MaskBuilder::MASK_MASTER,
                MaskBuilder::MASK_OWNER,
            ],

            self::PERMISSION_DELETE => [
                MaskBuilder::MASK_DELETE,
                MaskBuilder::MASK_OPERATOR,
                MaskBuilder::MASK_MASTER,
                MaskBuilder::MASK_OWNER,
            ],

            self::PERMISSION_UNDELETE => [
                MaskBuilder::MASK_UNDELETE,
                MaskBuilder::MASK_OPERATOR,
                MaskBuilder::MASK_MASTER,
                MaskBuilder::MASK_OWNER,
            ],

            self::PERMISSION_OPERATOR => [
                MaskBuilder::MASK_OPERATOR,
                MaskBuilder::MASK_MASTER,
                MaskBuilder::MASK_OWNER,
            ],

            self::PERMISSION_MASTER => [
                MaskBuilder::MASK_MASTER,
                MaskBuilder::MASK_OWNER,
            ],

            self::PERMISSION_OWNER => [
                MaskBuilder::MASK_OWNER,
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getMasks(string $permission, $object): ?array
    {
        if (!isset($this->map[$permission])) {
            return null;
        }

        return $this->map[$permission];
    }

    /**
     * {@inheritdoc}
     */
    public function contains(string $permission): bool
    {
        return isset($this->map[$permission]);
    }

    /**
     * {@inheritdoc}
     */
    public function getMaskBuilder(): MaskBuilder
    {
        return new MaskBuilder();
    }
}
