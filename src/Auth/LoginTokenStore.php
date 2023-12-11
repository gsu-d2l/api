<?php

declare(strict_types=1);

namespace GSU\D2L\API\Auth;

use GSU\D2L\API\Auth\D2LAuthAPIClient;
use GSU\D2L\API\D2LAPIConfig;

class LoginTokenStore
{
    protected ?LoginToken $loginToken = null;


    /**
     * @param D2LAPIConfig $config
     * @param D2LAuthAPIClient $authAPI
     */
    public function __construct(
        protected D2LAPIConfig $config,
        protected D2LAuthAPIClient $authAPI
    ) {
    }


    /**
     * @return LoginToken
     */
    public function getLoginToken(): LoginToken
    {
        if ($this->loginToken === null) {
            if (file_exists($this->config->loginTokenPath)) {
                $loginToken = file_get_contents($this->config->loginTokenPath);
                if (!is_string($loginToken)) {
                    throw new \RuntimeException("Error reading file: " . $this->config->loginTokenPath);
                }

                $loginToken = json_decode($loginToken, true, 2, JSON_THROW_ON_ERROR);
                if (!is_array($loginToken)) {
                    throw new \RuntimeException("Invalid contents in file: " . $this->config->loginTokenPath);
                }

                $this->loginToken = LoginToken::create($loginToken);
            }
        }

        if ($this->loginToken === null || $this->loginToken->isExpired()) {
            $this->loginToken = new LoginToken(
                $this->authAPI->login(),
                time() + (15 * 60)
            );
            $bytes = file_put_contents(
                $this->config->loginTokenPath,
                json_encode($this->loginToken, JSON_THROW_ON_ERROR)
            );
            if ($bytes === false) {
                throw new \RuntimeException("Error writing to file: " .  $this->config->loginTokenPath);
            }
        }

        return $this->loginToken;
    }
}
