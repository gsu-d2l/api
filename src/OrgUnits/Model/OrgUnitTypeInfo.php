<?php

declare(strict_types=1);

namespace GSU\D2L\API\OrgUnits\Model;

use mjfklib\Utils\ArrayValue;

class OrgUnitTypeInfo
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            Id: ArrayValue::getString($values, 'Id'),
            Code: ArrayValue::getString($values, 'Code'),
            Name: ArrayValue::getString($values, 'Name')
        );
    }


    /**
     * @param string $Id
     * @param string $Code
     * @param string $Name
     */
    public function __construct(
        public string $Id,
        public string $Code,
        public string $Name
    ) {
    }
}
