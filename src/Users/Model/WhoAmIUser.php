<?php

declare(strict_types=1);

namespace GSU\D2L\API\Users\Model;

use mjfklib\Utils\ArrayValue;

class WhoAmIUser
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
            FirstName: ArrayValue::getString($values, 'FirstName'),
            LastName: ArrayValue::getString($values, 'LastName'),
            UniqueName: ArrayValue::getString($values, 'UniqueName'),
            ProfileIdentifier: ArrayValue::getString($values, 'ProfileIdentifier'),
            Pronouns: ArrayValue::getString($values, 'Pronouns'),
        );
    }


    /**
     * @param string $Identifier
     * @param string $FirstName
     * @param string $LastName
     * @param string $UniqueName
     * @param string $ProfileIdentifier
     * @param string $Pronouns
     */
    public function __construct(
        public string $Identifier,
        public string $FirstName,
        public string $LastName,
        public string $UniqueName,
        public string $ProfileIdentifier,
        public string $Pronouns
    ) {
    }
}
