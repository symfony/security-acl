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

namespace Symfony\Component\Security\Acl\Permission;

/**
 * This abstract class implements nearly all the MaskBuilderInterface methods.
 */
abstract class AbstractMaskBuilder implements MaskBuilderInterface
{
    protected int $mask;

    public function __construct(int $mask = 0)
    {
        $this->set($mask);
    }

    /**
     * {@inheritdoc}
     */
    public function set(int $mask): static
    {
        $this->mask = $mask;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function get(): int
    {
        return $this->mask;
    }

    /**
     * {@inheritdoc}
     */
    public function add(string|int $mask): static
    {
        $this->mask |= $this->resolveMask($mask);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function remove(string|int $mask): static
    {
        $this->mask &= ~$this->resolveMask($mask);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function reset(): static
    {
        $this->mask = 0;

        return $this;
    }
}
