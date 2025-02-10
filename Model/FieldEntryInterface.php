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

namespace Symfony\Component\Security\Acl\Model;

/**
 * Interface for entries which are restricted to specific fields.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface FieldEntryInterface extends EntryInterface
{
    /**
     * Returns the field used for this entry.
     */
    public function getField(): string;
}
