<?php

declare(strict_types=1);

namespace GSU\D2L\API;

use mjfklib\Container\DefinitionSource;
use mjfklib\Container\Env;
use mjfklib\HttpClient\HttpClientDefinitionSource;

class D2LAPIDefinitionSource extends DefinitionSource
{
    /**
     * @inheritdoc
     */
    protected function createDefinitions(Env $env): array
    {
        return [
            D2LAPIConfig::class => static::factory([D2LAPIConfig::class, 'create'], [
                'values' => $env
            ])
        ];
    }


    /**
     * @inheritdoc
     */
    public function getSources(): array
    {
        return [
            HttpClientDefinitionSource::class
        ];
    }
}
