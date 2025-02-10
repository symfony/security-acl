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
 * This class allows you to build cumulative permissions easily, or convert
 * masks to a human-readable format.
 *
 * <code>
 *       $builder = new MaskBuilder();
 *       $builder
 *           ->add('view')
 *           ->add('create')
 *           ->add('edit')
 *       ;
 *       var_dump($builder->get());        // int(7)
 *       var_dump($builder->getPattern()); // string(32) ".............................ECV"
 * </code>
 *
 * We have defined some commonly used base permissions which you can use:
 * - VIEW: the SID is allowed to view the domain object / field
 * - CREATE: the SID is allowed to create new instances of the domain object / fields
 * - EDIT: the SID is allowed to edit existing instances of the domain object / field
 * - DELETE: the SID is allowed to delete domain objects
 * - UNDELETE: the SID is allowed to recover domain objects from trash
 * - OPERATOR: the SID is allowed to perform any action on the domain object
 *             except for granting others permissions
 * - MASTER: the SID is allowed to perform any action on the domain object,
 *           and is allowed to grant other SIDs any permission except for
 *           MASTER and OWNER permissions
 * - OWNER: the SID is owning the domain object in question and can perform any
 *          action on the domain object as well as grant any permission
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class MaskBuilder extends AbstractMaskBuilder
{
    public const MASK_VIEW = 1;           // 1 << 0
    public const MASK_CREATE = 2;         // 1 << 1
    public const MASK_EDIT = 4;           // 1 << 2
    public const MASK_DELETE = 8;         // 1 << 3
    public const MASK_UNDELETE = 16;      // 1 << 4
    public const MASK_OPERATOR = 32;      // 1 << 5
    public const MASK_MASTER = 64;        // 1 << 6
    public const MASK_OWNER = 128;        // 1 << 7
    public const MASK_IDDQD = 1073741823; // 1 << 0 | 1 << 1 | ... | 1 << 30

    public const CODE_VIEW = 'V';
    public const CODE_CREATE = 'C';
    public const CODE_EDIT = 'E';
    public const CODE_DELETE = 'D';
    public const CODE_UNDELETE = 'U';
    public const CODE_OPERATOR = 'O';
    public const CODE_MASTER = 'M';
    public const CODE_OWNER = 'N';

    public const ALL_OFF = '................................';
    public const OFF = '.';
    public const ON = '*';

    /**
     * Returns a human-readable representation of the permission.
     */
    public function getPattern(): string
    {
        $pattern = self::ALL_OFF;
        $length = \strlen($pattern);
        $bitmask = str_pad(decbin($this->mask), $length, '0', \STR_PAD_LEFT);

        for ($i = $length - 1; $i >= 0; --$i) {
            if ('1' === $bitmask[$i]) {
                try {
                    $pattern[$i] = self::getCode(1 << ($length - $i - 1));
                } catch (\Exception $e) {
                    $pattern[$i] = self::ON;
                }
            }
        }

        return $pattern;
    }

    /**
     * Returns the code for the passed mask.
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    public static function getCode(int $mask): string
    {
        $reflection = new \ReflectionClass(static::class);
        foreach ($reflection->getConstants() as $name => $cMask) {
            if (!str_starts_with($name, 'MASK_') || $mask !== $cMask) {
                continue;
            }

            if (!\defined($cName = 'static::CODE_'.substr($name, 5))) {
                throw new \RuntimeException('There was no code defined for this mask.');
            }

            return \constant($cName);
        }

        throw new \InvalidArgumentException(sprintf('The mask "%d" is not supported.', $mask));
    }

    /**
     * Returns the mask for the passed code.
     *
     * @throws \InvalidArgumentException
     */
    public function resolveMask(string|int $code): int
    {
        if (\is_string($code)) {
            if (!\defined($name = sprintf('static::MASK_%s', strtoupper($code)))) {
                throw new \InvalidArgumentException(sprintf('The code "%s" is not supported', $code));
            }

            return \constant($name);
        }

        return $code;
    }
}
