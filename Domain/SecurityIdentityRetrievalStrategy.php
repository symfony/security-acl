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

use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityRetrievalStrategyInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;

/**
 * Strategy for retrieving security identities.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class SecurityIdentityRetrievalStrategy implements SecurityIdentityRetrievalStrategyInterface
{
    public function __construct(
        private readonly RoleHierarchyInterface $roleHierarchy,
        private readonly AuthenticationTrustResolverInterface $authenticationTrustResolver,
    ) {
    }

    /**
     * {@inheritdoc}
     *
     * @return SecurityIdentityInterface[]
     */
    public function getSecurityIdentities(TokenInterface $token): array
    {
        $sids = [];

        // add user security identity
        if (!$token instanceof NullToken) {
            try {
                $sids[] = UserSecurityIdentity::fromToken($token);
            } catch (\InvalidArgumentException $e) {
                // ignore, user has no user security identity
            }
        }

        // add all reachable roles
        foreach ($this->roleHierarchy->getReachableRoleNames($token->getRoleNames()) as $role) {
            $sids[] = new RoleSecurityIdentity($role);
        }

        // add built-in special roles
        if ($this->authenticationTrustResolver->isFullFledged($token)) {
            $sids[] = new RoleSecurityIdentity(AuthenticatedVoter::IS_AUTHENTICATED_FULLY);
            $sids[] = new RoleSecurityIdentity(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED);
            $this->addAnonymousRoles($sids);
        } elseif ($this->authenticationTrustResolver->isRememberMe($token)) {
            $sids[] = new RoleSecurityIdentity(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED);
            $this->addAnonymousRoles($sids);
        } elseif ($this->isNotAuthenticated($token)) {
            $this->addAnonymousRoles($sids);
        }

        return $sids;
    }

    private function isNotAuthenticated(TokenInterface $token): bool
    {
        return !$this->authenticationTrustResolver->isAuthenticated($token);
    }

    /**
     * @param SecurityIdentityInterface[] &$sids
     */
    private function addAnonymousRoles(array &$sids): void
    {
        $sids[] = new RoleSecurityIdentity('IS_AUTHENTICATED_ANONYMOUSLY');
        if (\defined('\Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter::PUBLIC_ACCESS')) {
            $sids[] = new RoleSecurityIdentity(AuthenticatedVoter::PUBLIC_ACCESS);
        }
    }
}
