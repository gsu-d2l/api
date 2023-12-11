<?php

declare(strict_types=1);

namespace GSU\D2L\API\DataHub\Model;

use mjfklib\Utils\ArrayValue;

class BDSInfo
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            SchemaId: ArrayValue::getString($values, 'SchemaId'),
            Full: !is_null($values['Full'] ?? null)
                ? BDSPluginInfo::create(ArrayValue::getArray($values, 'Full'))
                : null,
            Differential: !is_null($values['Differential'] ?? null)
                ? BDSPluginInfo::create(ArrayValue::getArray($values, 'Differential'))
                : null,
            ExtractsLink: ArrayValue::getString($values, 'ExtractsLink')
        );
    }


    /** @var string $Name */
    public readonly string $Name;


    /**
     * @param string $SchemaId
     * @param BDSPluginInfo|null $Full
     * @param BDSPluginInfo|null $Differential
     * @param string $ExtractsLink
     */
    public function __construct(
        public readonly string $SchemaId,
        public readonly ?BDSPluginInfo $Full,
        public readonly ?BDSPluginInfo $Differential,
        public readonly string $ExtractsLink
    ) {
        $this->Name = $this->Full?->Name ?? $this->SchemaId;
    }
}
