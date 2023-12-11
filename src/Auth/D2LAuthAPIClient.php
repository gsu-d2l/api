<?php

declare(strict_types=1);

namespace GSU\D2L\API\Auth;

use GSU\D2L\API\D2LAPIConfig;
use mjfklib\HttpClient\HttpAPIClient;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

class D2LAuthAPIClient extends HttpAPIClient
{
    public const D2L_LOGIN_URI       = '/d2l/lp/auth/login/login.d2l';
    public const D2L_HOME_URI        = '/d2l/home';
    public const PKCE_VERIFIER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    public const PKCE_CHALLENGE_MODE = 'S256';


    /**
     * @param D2LAPIConfig $config
     * @param RequestFactoryInterface $requestFactory
     * @param ClientInterface $client
     */
    public function __construct(
        protected D2LAPIConfig $config,
        RequestFactoryInterface $requestFactory,
        ClientInterface $client,
    ) {
        parent::__construct($requestFactory, $client);
    }


    /**
     * @param string $method
     * @param UriInterface|string $uri
     * @return RequestInterface
     */
    public function createRequest(
        string $method,
        mixed $uri
    ): RequestInterface {
        if (is_string($uri) && str_starts_with($uri, '/')) {
            $uri = $this->config->d2lHost . $uri;
        }

        return parent::createRequest($method, $uri);
    }


    /**
     * @return array{0:string,1:string}
     */
    public static function generatePKCEVerifier(): array
    {
        $size = random_int(43, 128);

        /** @var int[]|false $bytes */
        $bytes = unpack("C{$size}", random_bytes($size));
        if ($bytes === false) {
            throw new \Random\RandomError("Unable to generate random number to use in PKCE verifier");
        }

        $codeVerifier = join(
            array_map(
                fn (int $v): string => substr(
                    static::PKCE_VERIFIER_CHARS,
                    $v % strlen(static::PKCE_VERIFIER_CHARS),
                    1
                ),
                $bytes
            )
        );

        $codeChallenge = base64_encode(hash('SHA256', $codeVerifier, true));

        return [$codeVerifier, $codeChallenge];
    }


    /**
     * @param string $refreshToken
     * @return OAuthToken
     */
    public function refreshOAuthToken(string $refreshToken): OAuthToken
    {
        $createdOn = time();

        $response = $this->sendRequest(
            $this->addRequestParams(
                $this->createRequest('POST', $this->config->oauthAccessTokenURL),
                [
                    'grant_type'    => 'refresh_token',
                    'client_id'     => $this->config->oauthClientId,
                    'client_secret' => $this->config->oauthClientSecret,
                    'refresh_token' => $refreshToken,
                ]
            ),
            200
        );

        $oauthTokenValues = $this->getResponseValues($response);
        $oauthTokenValues['created_on'] = $createdOn;

        return OAuthToken::create($oauthTokenValues);
    }


    /**
     * @param ?string $authCode
     * @param ?string $codeVerifier
     * @return OAuthToken
     */
    public function createOAuthToken(
        ?string $authCode = null,
        ?string $codeVerifier = null
    ): OAuthToken {
        $createdOn = time();

        if ($authCode === null) {
            list($authCode, $codeVerifier) = $this->createAuthCode();
        }

        $response = $this->sendRequest(
            $this->addRequestParams(
                $this->createRequest('POST', $this->config->oauthAccessTokenURL),
                [
                    'grant_type'    => 'authorization_code',
                    'client_id'     => $this->config->oauthClientId,
                    'client_secret' => $this->config->oauthClientSecret,
                    'redirect_uri'  => $this->config->oauthRedirectURI,
                    'code'          => $authCode,
                    'code_verifier' => $codeVerifier
                ]
            ),
            200
        );

        $oauthTokenValues = $this->getResponseValues($response);
        $oauthTokenValues['created_on'] = $createdOn;

        return OAuthToken::create($oauthTokenValues);
    }


    /**
     * @param ?string $loginToken
     * @return array{0:string,1:string}
     */
    public function createAuthCode(?string $loginToken = null): array
    {
        $loginToken ??= $this->login();

        $state = base64_encode(random_bytes(12));
        list($codeVerifier, $codeChallenge) = self::generatePKCEVerifier();

        $url = self::buildURL(
            $this->config->oauthAuthCodeURL,
            [
                'response_type'         => 'code',
                'client_id'             => $this->config->oauthClientId,
                'redirect_uri'          => $this->config->oauthRedirectURI,
                'scope'                 => $this->config->oauthScope,
                'state'                 => $state,
                'code_challenge'        => $codeChallenge,
                'code_challenge_method' => static::PKCE_CHALLENGE_MODE
            ]
        );

        do {
            $request = $this->createRequest('GET', $url);
            if (str_starts_with($url, $this->config->d2lHost)) {
                $request = $request->withHeader('Cookie', $loginToken);
            }
            $response = $this->sendRequest($request, 302);
            $url = $response->getHeader('Location')[0] ?? null;
        } while ($url !== null && !str_starts_with($url, $this->config->oauthRedirectURI));

        if ($url === null) {
            throw new \RuntimeException("Error creating authorization code");
        }

        if (str_starts_with($url, $this->config->oauthRedirectURI . '/?')) {
            $url = substr($url, strlen($this->config->oauthRedirectURI . '/?'));
        } else {
            $url = substr($url, strlen($this->config->oauthRedirectURI . '?'));
        }

        /** @var array<string,string> $params */
        $params = array_map(
            fn ($v) => urldecode($v),
            array_column(array_map(fn ($v) => explode('=', $v), explode("&", $url)), 1, 0)
        );

        if (($params['state'] ?? '') !== $state) {
            throw new \RuntimeException("Response state mismatch");
        }

        if (strlen($params['code'] ?? '') < 1) {
            throw new \RuntimeException("Authorization code is empty");
        }

        return [urldecode($params['code']), $codeVerifier];
    }


    /**
     * @param ?string $user
     * @param ?string $pass
     * @return string
     */
    public function login(
        ?string $user = null,
        ?string $pass = null
    ): string {
        $user ??= $this->config->d2lUser;
        $pass ??= $this->config->d2lPass;

        if ($user === '' || $pass === '') {
            throw new \RuntimeException("Username/password are empty");
        }

        $response = $this->sendRequest(
            $this->addRequestParams(
                $this->createRequest('POST', self::D2L_LOGIN_URI),
                [
                    'd2l_referrer' => '',
                    'noredirect'   => '1',
                    'loginPath'    => self::D2L_LOGIN_URI,
                    'userName'     => $user,
                    'password'     => $pass
                ]
            ),
            302
        );

        if (!in_array(self::D2L_HOME_URI, $response->getHeader('Location'), true)) {
            throw new \RuntimeException("Error logging in");
        }

        return implode("; ", array_map(
            fn ($v) => trim(explode(";", $v)[0] ?? ''),
            $response->getHeader("Set-Cookie")
        ));
    }
}
