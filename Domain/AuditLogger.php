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

namespace Symfony\Component\Security\Acl\Domain;

use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Symfony\Component\Security\Acl\Model\AuditLoggerInterface;
use Symfony\Component\Security\Acl\Model\EntryInterface;

/**
 * Base audit logger implementation.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
abstract class AuditLogger implements AuditLoggerInterface
{
    /**
     * Performs some checks if logging was requested.
     */
    public function logIfNeeded(bool $granted, EntryInterface $ace): void
    {
        if (!$ace instanceof AuditableEntryInterface) {
            return;
        }

        if ($granted && $ace->isAuditSuccess()) {
            $this->doLog($granted, $ace);
        } elseif (!$granted && $ace->isAuditFailure()) {
            $this->doLog($granted, $ace);
        }
    }

    /**
     * This method is only called when logging is needed.
     */
    abstract protected function doLog(bool $granted, EntryInterface $ace): void;
}
