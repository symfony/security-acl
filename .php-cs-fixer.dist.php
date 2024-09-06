<?php

return (new PhpCsFixer\Config())
    ->setRules([
        '@PHP71Migration' => true,
        '@PHPUnit75Migration:risky' => true,
        '@Symfony' => true,
        '@Symfony:risky' => true,
        'protected_to_private' => false,
        'phpdoc_to_comment' => ['ignored_tags' => ['psalm-suppress']],
    ])
    ->setRiskyAllowed(true)
    ->setFinder(
        (new PhpCsFixer\Finder())
            ->in(__DIR__)
            ->append([__FILE__])
    )
;
