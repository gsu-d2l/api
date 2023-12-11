<?php

declare(strict_types=1);

namespace GSU\D2L\API\Users\Model;

use mjfklib\Utils\ArrayValue;

class UpdateUserData
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            OrgDefinedId: ArrayValue::getString($values, 'OrgDefinedId'),
            FirstName: ArrayValue::getString($values, 'FirstName'),
            MiddleName: ArrayValue::getStringNull($values, 'MiddleName'),
            LastName: ArrayValue::getString($values, 'LastName'),
            ExternalEmail: ArrayValue::getStringNull($values, 'ExternalEmail'),
            UserName: ArrayValue::getString($values, 'UserName'),
            Activation: UserActivationData::create(ArrayValue::getArray($values, 'Activation')),
            Pronouns: ArrayValue::getStringNull($values, 'Pronouns'),
        );
    }


    /**
     * @param string $OrgDefinedId
     * @param string $FirstName
     * @param string|null $MiddleName
     * @param string $LastName
     * @param string|null $ExternalEmail
     * @param string $UserName
     * @param UserActivationData $Activation
     * @param string|null $Pronouns
     */
    public function __construct(
        public string $OrgDefinedId,
        public string $FirstName,
        public ?string $MiddleName,
        public string $LastName,
        public ?string $ExternalEmail,
        public string $UserName,
        public UserActivationData $Activation,
        public ?string $Pronouns
    ) {
    }
}
