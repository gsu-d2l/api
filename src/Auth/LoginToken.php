<?php

declare(strict_types=1);

namespace GSU\D2L\API\Auth;

use mjfklib\Utils\ArrayValue;

class LoginToken
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            token: ArrayValue::getString($values, 'token'),
            expires_on: ArrayValue::getInt($values, 'expires_on')
        );
    }


    /**
     * @param string $token
     * @param int $expires_on
     */
    public function __construct(
        public string $token,
        public int $expires_on
    ) {
    }


    /**
     * @return bool
     */
    public function isExpired(): bool
    {
        return time() >= $this->expires_on;
    }
}
