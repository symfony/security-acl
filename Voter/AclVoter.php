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

use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Exception\NoAceFoundException;
use Symfony\Component\Security\Acl\Model\AclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityRetrievalStrategyInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityRetrievalStrategyInterface;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

if (class_exists(\Symfony\Component\Security\Core\Security::class)) {
    /**
     * @internal
     */
    trait AclVoterTrait
    {
        /**
         * @param mixed[] $attributes
         *
         * @return int<-1,1>
         */
        public function vote(TokenInterface $token, $subject, array $attributes)
        {
            return $this->doVote($token, $subject, $attributes);
        }
    }
} else {
    /**
     * @internal
     */
    trait AclVoterTrait
    {
        /**
         * @param mixed[] $attributes
         *
         * @return int<-1,1>
         */
        public function vote(TokenInterface $token, mixed $subject, array $attributes): int
        {
            return $this->doVote($token, $subject, $attributes);
        }
    }
}

/**
 * This voter can be used as a base class for implementing your own permissions.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class AclVoter implements VoterInterface
{
    use AclVoterTrait;

    public function __construct(
        private readonly AclProviderInterface $aclProvider,
        private readonly ObjectIdentityRetrievalStrategyInterface $objectIdentityRetrievalStrategy,
        private readonly SecurityIdentityRetrievalStrategyInterface $securityIdentityRetrievalStrategy,
        private readonly PermissionMapInterface $permissionMap,
        private readonly ?LoggerInterface $logger = null,
        private readonly bool $allowIfObjectIdentityUnavailable = true,
    ) {
    }

    public function supportsAttribute(mixed $attribute): bool
    {
        return \is_string($attribute) && $this->permissionMap->contains($attribute);
    }

    /**
     * @param mixed[] $attributes
     */
    private function doVote(TokenInterface $token, mixed $subject, array $attributes): int
    {
        foreach ($attributes as $attribute) {
            if (!$this->supportsAttribute($attribute)) {
                continue;
            }

            if (null === $masks = $this->permissionMap->getMasks($attribute, $subject)) {
                continue;
            }

            if (null === $subject) {
                if (null !== $this->logger) {
                    $this->logger->debug(sprintf('Object identity unavailable. Voting to %s.', $this->allowIfObjectIdentityUnavailable ? 'grant access' : 'abstain'));
                }

                return $this->allowIfObjectIdentityUnavailable ? self::ACCESS_GRANTED : self::ACCESS_ABSTAIN;
            } elseif ($subject instanceof FieldVote) {
                $field = $subject->getField();
                $subject = $subject->getDomainObject();
            } else {
                $field = null;
            }

            if ($subject instanceof ObjectIdentityInterface) {
                $oid = $subject;
            } elseif (null === $oid = $this->objectIdentityRetrievalStrategy->getObjectIdentity($subject)) {
                if (null !== $this->logger) {
                    $this->logger->debug(sprintf('Object identity unavailable. Voting to %s.', $this->allowIfObjectIdentityUnavailable ? 'grant access' : 'abstain'));
                }

                return $this->allowIfObjectIdentityUnavailable ? self::ACCESS_GRANTED : self::ACCESS_ABSTAIN;
            }

            if (!$this->supportsClass($oid->getType())) {
                return self::ACCESS_ABSTAIN;
            }

            $sids = $this->securityIdentityRetrievalStrategy->getSecurityIdentities($token);

            try {
                $acl = $this->aclProvider->findAcl($oid, $sids);

                if (null === $field && $acl->isGranted($masks, $sids, false)) {
                    if (null !== $this->logger) {
                        $this->logger->debug('ACL found, permission granted. Voting to grant access.');
                    }

                    return self::ACCESS_GRANTED;
                } elseif (null !== $field && $acl->isFieldGranted($field, $masks, $sids, false)) {
                    if (null !== $this->logger) {
                        $this->logger->debug('ACL found, permission granted. Voting to grant access.');
                    }

                    return self::ACCESS_GRANTED;
                }

                if (null !== $this->logger) {
                    $this->logger->debug('ACL found, insufficient permissions. Voting to deny access.');
                }

                return self::ACCESS_DENIED;
            } catch (AclNotFoundException $e) {
                if (null !== $this->logger) {
                    $this->logger->debug('No ACL found for the object identity. Voting to deny access.');
                }

                return self::ACCESS_DENIED;
            } catch (NoAceFoundException $e) {
                if (null !== $this->logger) {
                    $this->logger->debug('ACL found, no ACE applicable. Voting to deny access.');
                }

                return self::ACCESS_DENIED;
            }
        }

        // no attribute was supported
        return self::ACCESS_ABSTAIN;
    }

    /**
     * You can override this method when writing a voter for a specific domain
     * class.
     */
    public function supportsClass(string $class): bool
    {
        return true;
    }
}
