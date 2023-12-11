<?php

declare(strict_types=1);

namespace GSU\D2L\API\OrgUnits\Model;

use mjfklib\Utils\ArrayValue;

class OrgUnit
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            Identifier: ArrayValue::getString($values, 'Identifier'),
            Name: ArrayValue::getString($values, 'Name'),
            Code: ArrayValue::getStringNull($values, 'Code'),
            Type: OrgUnitTypeInfo::create(ArrayValue::getArray($values, 'Type'))
        );
    }


    /**
     * @param string $Identifier
     * @param string $Name
     * @param string|null $Code
     */
    public function __construct(
        public string $Identifier,
        public string $Name,
        public ?string $Code,
        public OrgUnitTypeInfo $Type,
    ) {
    }
}
