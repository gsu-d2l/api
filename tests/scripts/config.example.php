<?php

declare(strict_types=1);

return [
    'd2lHost' => $env['D2L_HOST'] ?? '',
    'd2lUser' => $env['D2L_USER'] ?? '',
    'd2lPass' => $env['D2L_PASS'] ?? '',
    'd2lLPVersion' => $env['D2L_LP_VERSION'] ?? null,
    'd2lLEVersion' => $env['D2L_LE_VERSION'] ?? null,
    'loginTokenPath' => $env['D2L_LOGIN_TOKEN_PATH'] ?? __DIR__ . '/login_token.json',
    'oauthTokenPath' => $env['D2L_OAUTH_TOKEN_PATH'] ?? __DIR__ . '/oauth_token.json',
    'oauthClientId' => $env['D2L_OAUTH_CLIENT_ID'] ?? '',
    'oauthClientSecret' => $env['D2L_OAUTH_CLIENT_SECRET'] ?? '',
    'oauthRedirectURI' => $env['D2L_OAUTH_REDIRECT_URI'] ?? '',
    'oauthScope' => $env['D2L_OAUTH_SCOPE'] ?? implode(' ', [
        'core:*:*',
    ]),
    'oauthAuthCodeURL' => $env['D2L_OAUTH_AUTH_CODE_URL'] ?? null,
    'oauthAccessTokenURL' => $env['D2L_OAUTH_ACCESS_TOKEN_URL'] ?? null,
];
