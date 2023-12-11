<?php

declare(strict_types=1);

namespace GSU\D2L\API\Users\Model;

use mjfklib\Utils\ArrayValue;

class UserActivationData
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            IsActive: ArrayValue::getBool($values, 'IsActive')
        );
    }


    /**
     * @param bool $IsActive
     */
    public function __construct(public bool $IsActive)
    {
    }
}
