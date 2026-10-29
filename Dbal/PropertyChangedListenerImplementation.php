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

use Doctrine\Persistence\PropertyChangedListener;

if ((new \ReflectionMethod(PropertyChangedListener::class, 'propertyChanged'))->hasReturnType()) {
    /** @internal */
    trait PropertyChangedListenerImplementation
    {
        /**
         * Implementation of PropertyChangedListener.
         *
         * This allows us to keep track of which values have been changed, so we don't
         * have to do a full introspection when ->updateAcl() is called.
         *
         * @param mixed  $sender
         * @param string $propertyName
         * @param mixed  $oldValue
         * @param mixed  $newValue
         *
         * @throws \InvalidArgumentException
         */
        public function propertyChanged($sender, $propertyName, $oldValue, $newValue): void
        {
            $this->doPropertyChanged($sender, $propertyName, $oldValue, $newValue);
        }
    }
} else {
    /** @internal */
    trait PropertyChangedListenerImplementation
    {
        /**
         * Implementation of PropertyChangedListener.
         *
         * This allows us to keep track of which values have been changed, so we don't
         * have to do a full introspection when ->updateAcl() is called.
         *
         * @param mixed  $sender
         * @param string $propertyName
         * @param mixed  $oldValue
         * @param mixed  $newValue
         *
         * @return void
         *
         * @throws \InvalidArgumentException
         */
        public function propertyChanged($sender, $propertyName, $oldValue, $newValue)
        {
            $this->doPropertyChanged($sender, $propertyName, $oldValue, $newValue);
        }
    }
}
