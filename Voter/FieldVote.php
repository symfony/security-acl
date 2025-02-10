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

namespace Symfony\Component\Security\Acl\Voter;

/**
 * This class is a lightweight wrapper around field vote requests which does
 * not violate any interface contracts.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class FieldVote
{
    public function __construct(
        private readonly object $domainObject,
        private readonly string $field,
    ) {
    }

    public function getDomainObject(): object
    {
        return $this->domainObject;
    }

    public function getField(): string
    {
        return $this->field;
    }
}
