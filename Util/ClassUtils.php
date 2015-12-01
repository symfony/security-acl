<?php

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
     * This class should not be instantiated.
     */
    private function __construct()
    {
    }

    /**
     * Gets the real class name of a class name that could be a proxy.
     *
     * @param string|object $object
     *
     * @return string
     */
    public static function getRealClass($object)
    {
        $class = is_object($object) ? get_class($object) : $object;

        if (class_exists('Doctrine\Common\Util\ClassUtils')) {
            return DoctrineClassUtils::getRealClass($class);
        }

        return $class;
    }
}
