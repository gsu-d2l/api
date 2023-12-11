<?php

declare(strict_types=1);

namespace GSU\D2L\API\Users\Model;

use mjfklib\Utils\ArrayValue;

class UserData
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            OrgId: ArrayValue::getInt($values, 'OrgId'),
            UserId: ArrayValue::getInt($values, 'UserId'),
            FirstName: ArrayValue::getString($values, 'FirstName'),
            MiddleName: ArrayValue::getStringNull($values, 'MiddleName'),
            LastName: ArrayValue::getString($values, 'LastName'),
            UserName: ArrayValue::getString($values, 'UserName'),
            ExternalEmail: ArrayValue::getStringNull($values, 'ExternalEmail'),
            OrgDefinedId: ArrayValue::getStringNull($values, 'OrgDefinedId'),
            UniqueIdentifier: ArrayValue::getString($values, 'UniqueIdentifier'),
            Activation: UserActivationData::create(ArrayValue::getArray($values, 'Activation')),
            LastAccessedDate: ArrayValue::getDateTimeNull($values, 'LastAccessedDate'),
            Pronouns: ArrayValue::getString($values, 'Pronouns'),
        );
    }


    /**
     * @param int $OrgId
     * @param int $UserId
     * @param string $FirstName
     * @param string|null $MiddleName
     * @param string $LastName
     * @param string $UserName
     * @param string|null $ExternalEmail
     * @param string|null $OrgDefinedId
     * @param string $UniqueIdentifier
     * @param UserActivationData $Activation
     * @param \DateTimeInterface|null $LastAccessedDate
     * @param string $Pronouns
     */
    public function __construct(
        public int $OrgId,
        public int $UserId,
        public string $FirstName,
        public ?string $MiddleName,
        public string $LastName,
        public string $UserName,
        public ?string $ExternalEmail,
        public ?string $OrgDefinedId,
        public string $UniqueIdentifier,
        public UserActivationData $Activation,
        public \DateTimeInterface|null $LastAccessedDate,
        public string $Pronouns
    ) {
    }
}
