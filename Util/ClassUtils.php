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

namespace Symfony\Component\Security\Acl\Util;

use Doctrine\Common\Util\ClassUtils as DoctrineClassUtils;

/**
 * Class related functionality for objects that
 * might or might not be proxy objects at the moment.
 *
 * @see DoctrineClassUtils
 *
 * @author Johannes Schmitt <schmittjoh@gmail.com>
 * @author Iltar van der Berg <kjarli@gmail.com>
 */
final class ClassUtils
{
    /**
     * Marker for Proxy class names.
     *
     * @var string
     */
    public const MARKER = '__CG__';

    /**
     * Length of the proxy marker.
     *
     * @var int
     */
    public const MARKER_LENGTH = 6;

    /**
     * This class should not be instantiated.
     */
    private function __construct()
    {
    }

    /**
     * Gets the real class name of a class name that could be a proxy.
     */
    public static function getRealClass(object|string $object): string
    {
        $class = \is_object($object) ? $object::class : $object;

        if (class_exists(DoctrineClassUtils::class)) {
            return DoctrineClassUtils::getRealClass($class);
        }

        // fallback in case doctrine common  is not installed
        if (false === $pos = strrpos($class, '\\'.self::MARKER.'\\')) {
            return $class;
        }

        return substr($class, $pos + self::MARKER_LENGTH + 2);
    }
}
