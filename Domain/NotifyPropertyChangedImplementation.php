<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Security\Acl\Domain;

use Doctrine\Persistence\NotifyPropertyChanged;
use Doctrine\Persistence\PropertyChangedListener;

if ((new \ReflectionMethod(NotifyPropertyChanged::class, 'addPropertyChangedListener'))->hasReturnType()) {
    /** @internal */
    trait NotifyPropertyChangedImplementation
    {
        /**
         * Adds a property changed listener.
         */
        public function addPropertyChangedListener(PropertyChangedListener $listener): void
        {
            $this->listeners[] = $listener;
        }
    }
} else {
    /** @internal */
    trait NotifyPropertyChangedImplementation
    {
        /**
         * Adds a property changed listener.
         *
         * @return void
         */
        public function addPropertyChangedListener(PropertyChangedListener $listener)
        {
            $this->listeners[] = $listener;
        }
    }
}
