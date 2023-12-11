<?php

declare(strict_types=1);

namespace GSU\D2L\API;

use mjfklib\Utils\ArrayValue;
use mjfklib\Container\Env;

class D2LAPIConfig
{
    public const D2L_HOST = 'D2L_HOST';
    public const D2L_USER = 'D2L_USER';
    public const D2L_PASS = 'D2L_PASS';
    public const D2L_LP_VERSION = 'D2L_LP_VERSION';
    public const D2L_LE_VERSION = 'D2L_LE_VERSION';
    public const D2L_LOGIN_TOKEN_PATH = 'D2L_LOGIN_TOKEN_PATH';
    public const D2L_OAUTH_TOKEN_PATH = 'D2L_OAUTH_TOKEN_PATH';
    public const D2L_OAUTH_CLIENT_ID = 'D2L_OAUTH_CLIENT_ID';
    public const D2L_OAUTH_CLIENT_SECRET = 'D2L_OAUTH_CLIENT_SECRET';
    public const D2L_OAUTH_REDIRECT_URI = 'D2L_OAUTH_REDIRECT_URI';
    public const D2L_OAUTH_SCOPE = 'D2L_OAUTH_SCOPE';
    public const D2L_OAUTH_AUTH_CODE_URL = 'D2L_OAUTH_AUTH_CODE_URL';
    public const D2L_OAUTH_ACCESS_TOKEN_URL = 'D2L_OAUTH_ACCESS_TOKEN_URL';

    public const D2L_LP_PREFIX = '/d2l/api/lp/';
    public const D2L_LE_PREFIX = '/d2l/api/le/';
    public const DEFAULT_D2L_LP_VERSION = '1.44';
    public const DEFAULT_D2L_LE_VERSION = '1.71';
    public const DEFAULT_OAUTH_AUTH_CODE_URL = 'https://auth.brightspace.com/oauth2/auth';
    public const DEFAULT_OAUTH_ACCESS_TOKEN_URL = 'https://auth.brightspace.com/core/connect/token';


    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ($values instanceof Env)
            ? [
                'd2lHost' => $values[self::D2L_HOST] ?? '',
                'd2lUser' => $values[self::D2L_USER] ?? '',
                'd2lPass' => $values[self::D2L_PASS] ?? '',
                'd2lLPVersion' => $values[self::D2L_LP_VERSION] ?? null,
                'd2lLEVersion' => $values[self::D2L_LE_VERSION] ?? null,
                'loginTokenPath' => $values[self::D2L_LOGIN_TOKEN_PATH] ?? '',
                'oauthTokenPath' => $values[self::D2L_OAUTH_TOKEN_PATH] ?? '',
                'oauthClientId' => $values[self::D2L_OAUTH_CLIENT_ID] ?? '',
                'oauthClientSecret' => $values[self::D2L_OAUTH_CLIENT_SECRET] ?? '',
                'oauthRedirectURI' => $values[self::D2L_OAUTH_REDIRECT_URI] ?? '',
                'oauthScope' => $values[self::D2L_OAUTH_SCOPE] ?? '',
                'oauthAuthCodeURL' => $values[self::D2L_OAUTH_AUTH_CODE_URL] ?? null,
                'oauthAccessTokenURL' => $values[self::D2L_OAUTH_ACCESS_TOKEN_URL] ?? null,
            ]
            : ArrayValue::convertToArray($values);

        return new self(
            d2lHost: ArrayValue::getString($values, 'd2lHost'),
            d2lUser: ArrayValue::getString($values, 'd2lUser'),
            d2lPass: ArrayValue::getString($values, 'd2lPass'),
            d2lLPVersion: ArrayValue::getStringNull($values, 'd2lLPVersion'),
            d2lLEVersion: ArrayValue::getStringNull($values, 'd2lLEVersion'),
            loginTokenPath: ArrayValue::getString($values, 'loginTokenPath'),
            oauthTokenPath: ArrayValue::getString($values, 'oauthTokenPath'),
            oauthClientId: ArrayValue::getString($values, 'oauthClientId'),
            oauthClientSecret: ArrayValue::getString($values, 'oauthClientSecret'),
            oauthRedirectURI: ArrayValue::getString($values, 'oauthRedirectURI'),
            oauthScope: ArrayValue::getString($values, 'oauthScope'),
            oauthAuthCodeURL: ArrayValue::getStringNull($values, 'oauthAuthCodeURL'),
            oauthAccessTokenURL: ArrayValue::getStringNull($values, 'oauthAccessTokenURL'),
        );
    }


    public string $d2lHost;
    public string $d2lUser;
    public string $d2lPass;
    public string $d2lLPPrefix;
    public string $d2lLEPrefix;
    public string $loginTokenPath;
    public string $oauthTokenPath;
    public string $oauthClientId;
    public string $oauthClientSecret;
    public string $oauthRedirectURI;
    public string $oauthScope;
    public string $oauthAuthCodeURL;
    public string $oauthAccessTokenURL;


    /**
     * @param string $d2lHost
     * @param string $d2lUser
     * @param string $d2lPass
     * @param string|null $d2lLPVersion
     * @param string|null $d2lLEVersion
     * @param string $loginTokenPath
     * @param string $oauthTokenPath
     * @param string $oauthClientId
     * @param string $oauthClientSecret
     * @param string $oauthRedirectURI
     * @param string $oauthScope
     * @param string|null $oauthAuthCodeURL
     * @param string|null $oauthAccessTokenURL
     */
    public function __construct(
        string $d2lHost,
        string $d2lUser,
        string $d2lPass,
        string|null $d2lLPVersion,
        string|null $d2lLEVersion,
        string $loginTokenPath,
        string $oauthTokenPath,
        string $oauthClientId,
        string $oauthClientSecret,
        string $oauthRedirectURI,
        string $oauthScope,
        string|null $oauthAuthCodeURL,
        string|null $oauthAccessTokenURL,
    ) {
        $this->d2lHost = $d2lHost;
        $this->d2lUser = $d2lUser;
        $this->d2lPass = $d2lPass;
        $this->d2lLPPrefix = self::D2L_LP_PREFIX . ($d2lLPVersion ?? self::DEFAULT_D2L_LP_VERSION);
        $this->d2lLEPrefix = self::D2L_LE_PREFIX . ($d2lLEVersion ?? self::DEFAULT_D2L_LE_VERSION);
        $this->loginTokenPath = $loginTokenPath;
        $this->oauthTokenPath = $oauthTokenPath;
        $this->oauthClientId = $oauthClientId;
        $this->oauthClientSecret = $oauthClientSecret;
        $this->oauthRedirectURI = $oauthRedirectURI;
        $this->oauthScope = $oauthScope;
        $this->oauthAuthCodeURL = $oauthAuthCodeURL ?? self::DEFAULT_OAUTH_AUTH_CODE_URL;
        $this->oauthAccessTokenURL = $oauthAccessTokenURL ?? self::DEFAULT_OAUTH_ACCESS_TOKEN_URL;
    }
}
