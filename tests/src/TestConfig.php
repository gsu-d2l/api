<?php

declare(strict_types=1);

namespace Test\GSU\D2L\API;

use GSU\D2L\API\D2LAPIConfig;

class TestConfig extends D2LAPIConfig
{
    public const D2L_HOST                   = 'https://my.lms';
    public const D2L_USER                   = 'test_user';
    public const D2L_PASS                   = 'K33p1tS3cret!';
    public const D2L_LP_VERSION             = null;
    public const D2L_LE_VERSION             = null;
    public const D2L_LOGIN_TOKEN_PATH       = __DIR__ . '/../work/login_token.json';
    public const D2L_OAUTH_TOKEN_PATH       = __DIR__ . '/../work/oauth_token.json';
    public const D2L_OAUTH_CLIENT_ID        = '1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d';
    public const D2L_OAUTH_CLIENT_SECRET    = 'TisuUk9IR0_p8Xm-lvaVh6M2MtImhqQyw0ZS50UHBB';
    public const D2L_OAUTH_REDIRECT_URI     = 'https://my.app';
    public const D2L_OAUTH_SCOPE            = 'core:*:*';
    public const D2L_OAUTH_AUTH_CODE_URL    = null;
    public const D2L_OAUTH_ACCESS_TOKEN_URL = null;


    public function __construct()
    {
        parent::__construct(
            d2lHost: self::D2L_HOST,
            d2lUser: self::D2L_USER,
            d2lPass: self::D2L_PASS,
            d2lLPVersion: self::D2L_LP_VERSION,
            d2lLEVersion: self::D2L_LE_VERSION,
            loginTokenPath: self::D2L_LOGIN_TOKEN_PATH,
            oauthTokenPath: self::D2L_OAUTH_TOKEN_PATH,
            oauthClientId: self::D2L_OAUTH_CLIENT_ID,
            oauthClientSecret: self::D2L_OAUTH_CLIENT_SECRET,
            oauthRedirectURI: self::D2L_OAUTH_REDIRECT_URI,
            oauthScope: self::D2L_OAUTH_SCOPE,
            oauthAuthCodeURL: self::D2L_OAUTH_AUTH_CODE_URL,
            oauthAccessTokenURL: self::D2L_OAUTH_ACCESS_TOKEN_URL,
        );
    }
}
