<?php

declare(strict_types=1);

namespace GSU\D2L\API\Core;

use GSU\D2L\API\D2LAPIConfig;
use GSU\D2L\API\Auth\LoginTokenStore;
use GSU\D2L\API\Auth\OAuthTokenStore;
use mjfklib\HttpClient\HttpAPIClient;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;

class D2LAPIClient extends HttpAPIClient
{
    /**
     * @param D2LAPIConfig $config
     * @param LoginTokenStore $loginTokenStore
     * @param OAuthTokenStore $oauthTokenStore
     * @param RequestFactoryInterface $requestFactory
     * @param ClientInterface $client
     */
    public function __construct(
        protected D2LAPIConfig $config,
        protected LoginTokenStore $loginTokenStore,
        protected OAuthTokenStore $oauthTokenStore,
        RequestFactoryInterface $requestFactory,
        ClientInterface $client
    ) {
        parent::__construct($requestFactory, $client);
    }


    /**
     * @param string $method
     * @param UriInterface|string $uri
     * @param bool $forceAuth
     * @param bool $useOAuth
     * @return RequestInterface
     */
    public function createRequest(
        string $method,
        mixed $uri,
        bool $forceAuth = false,
        bool $useOAuth = true
    ): RequestInterface {
        if (is_string($uri) && str_starts_with($uri, '/')) {
            $uri = $this->config->d2lHost . $uri;
        }

        $request = parent::createRequest($method, $uri);

        if ($forceAuth === true || str_starts_with(strval($request->getUri()), $this->config->d2lHost)) {
            if ($useOAuth) {
                $request = $request->withHeader(
                    "Authorization",
                    "Bearer " . $this->oauthTokenStore->getOAuthToken()->access_token
                );
            } else {
                $request = $request->withHeader(
                    "Cookie",
                    $this->loginTokenStore->getLoginToken()->token
                );
            }
        }

        return $request;
    }
}
