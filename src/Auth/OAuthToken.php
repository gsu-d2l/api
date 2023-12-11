<?php

declare(strict_types=1);

namespace GSU\D2L\API\Auth;

use mjfklib\Utils\ArrayValue;

class OAuthToken
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            access_token: ArrayValue::getString($values, 'access_token'),
            scope: ArrayValue::getString($values, 'scope'),
            expires_in: ArrayValue::getInt($values, 'expires_in'),
            refresh_token: ArrayValue::getString($values, 'refresh_token'),
            token_type: ArrayValue::getString($values, 'token_type'),
            created_on: ArrayValue::getIntNull($values, 'created_on') ?? 0,
            expires_on: ArrayValue::getIntNull($values, 'expires_on') ?? 0
        );
    }


    /**
     * @param string $access_token
     * @param string $scope
     * @param int $expires_in
     * @param string $refresh_token
     * @param string $token_type
     * @param int $created_on
     * @param int $expires_on
     */
    public function __construct(
        public string $access_token,
        public string $scope,
        public int $expires_in,
        public string $refresh_token,
        public string $token_type,
        public int $created_on = 0,
        public int $expires_on = 0,
    ) {
        if ($this->expires_on < 1) {
            $this->expires_on = $this->created_on + $this->expires_in;
        }
    }


    /**
     * @return bool
     */
    public function isExpired(): bool
    {
        return time() >= $this->expires_on;
    }
}
