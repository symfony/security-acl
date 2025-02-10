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
 * This interface adds auditing capabilities to the ACL.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface AuditableAclInterface extends MutableAclInterface
{
    /**
     * Updates auditing for class-based ACE.
     */
    public function updateClassAuditing(int $index, bool $auditSuccess, bool $auditFailure): void;

    /**
     * Updates auditing for class-field-based ACE.
     */
    public function updateClassFieldAuditing(int $index, string $field, bool $auditSuccess, bool $auditFailure): void;

    /**
     * Updates auditing for object-based ACE.
     */
    public function updateObjectAuditing(int $index, bool $auditSuccess, bool $auditFailure): void;

    /**
     * Updates auditing for object-field-based ACE.
     */
    public function updateObjectFieldAuditing(int $index, string $field, bool $auditSuccess, bool $auditFailure): void;
}
