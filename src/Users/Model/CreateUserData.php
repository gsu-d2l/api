<?php

declare(strict_types=1);

namespace GSU\D2L\API\Users\Model;

use mjfklib\Utils\ArrayValue;

class CreateUserData
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            OrgDefinedId: ArrayValue::getStringNull($values, 'OrgDefinedId'),
            FirstName: ArrayValue::getString($values, 'FirstName'),
            MiddleName: ArrayValue::getStringNull($values, 'MiddleName'),
            LastName: ArrayValue::getString($values, 'LastName'),
            ExternalEmail: ArrayValue::getStringNull($values, 'ExternalEmail'),
            UserName: ArrayValue::getString($values, 'UserName'),
            RoleId: ArrayValue::getInt($values, 'RoleId'),
            IsActive: ArrayValue::getBool($values, 'IsActive'),
            SendCreationEmail: ArrayValue::getBool($values, 'SendCreationEmail'),
            Pronouns: ArrayValue::getStringNull($values, 'Pronouns'),
        );
    }


    /**
     * @param string|null $OrgDefinedId
     * @param string $FirstName
     * @param string|null $MiddleName
     * @param string $LastName
     * @param string|null $ExternalEmail
     * @param string $UserName
     * @param int $RoleId
     * @param bool $IsActive
     * @param bool $SendCreationEmail
     * @param string|null $Pronouns
     */
    public function __construct(
        public ?string $OrgDefinedId,
        public string $FirstName,
        public ?string $MiddleName,
        public string $LastName,
        public ?string $ExternalEmail,
        public string $UserName,
        public int $RoleId,
        public bool $IsActive,
        public bool $SendCreationEmail,
        public ?string $Pronouns
    ) {
    }
}
