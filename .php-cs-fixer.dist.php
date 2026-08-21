<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in([__DIR__ . '/src', __DIR__ . '/tests'])
    ->name('*.php');

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        '@PSR12'                             => true,
        '@PHP82Migration'                    => true,
        'declare_strict_types'               => true,
        'strict_param'                       => true,
        'array_syntax'                       => ['syntax' => 'short'],
        'ordered_imports'                    => ['sort_algorithm' => 'alpha'],
        'no_unused_imports'                  => true,
        'single_quote'                       => true,
        'trailing_comma_in_multiline'        => ['elements' => ['arrays', 'arguments', 'parameters']],
        'phpdoc_align'                       => ['align' => 'left'],
        'binary_operator_spaces'             => ['default' => 'single_space'],
        'global_namespace_import'            => ['import_classes' => false, 'import_functions' => false],
    ])
    ->setFinder($finder);
