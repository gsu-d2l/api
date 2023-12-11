<?php

declare(strict_types=1);

namespace Test\GSU\D2L\API\Users;

use GuzzleHttp\Psr7\Response;
use Test\GSU\D2L\API\TestConfig;
use Test\GSU\D2L\API\TestEnv;
use GSU\D2L\API\Users\UsersAPI;
use mjfklib\HttpClient\Exception\BadRequestException;
use mjfklib\HttpClient\Exception\ForbiddenException;
use mjfklib\HttpClient\Exception\HttpException;
use mjfklib\HttpClient\Exception\NotFoundException;
use mjfklib\HttpClient\Exception\TooManyRequestsException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class WhoAmITest extends TestCase
{
    /** @var ClientInterface&MockObject $client */
    private ClientInterface $client;
    private TestEnv $env;
    private UsersAPI $api;


    /**
     * @param non-empty-string $name
     */
    public function __construct(string $name)
    {
        parent::__construct($name);

        $this->client = $this->createMock(ClientInterface::class);

        $this->env = new TestEnv(
            new TestConfig(),
            $this->client
        );

        $this->api = new UsersAPI(
            $this->env->config,
            $this->env->loginTokenStore,
            $this->env->oauthTokenStore,
            $this->env->httpRequestFactory,
            $this->env->httpClient
        );
    }


    /**
     * @param ResponseInterface $response
     * @return void
     */
    private function setResponse(ResponseInterface $response): void
    {
        $this->client
            ->expects(self::once())
            ->method('sendRequest')
            ->with(
                self::callback(
                    fn (RequestInterface $request): bool => $request->hasHeader('Authorization')
                        && $request->getMethod() === 'GET'
                        && $request->getUri()->getPath() === $this->env->config->d2lLPPrefix . '/users/whoami'
                )
            )
            ->willReturn($response);
    }


    /**
     * @return void
     */
    public function testSuccess(): void
    {
        $this->setResponse(new Response(
            status: 200,
            body: json_encode([
                'Identifier' => '12345',
                'FirstName' => '',
                'LastName' => '',
                'UniqueName' => '',
                'ProfileIdentifier' => '',
                'Pronouns' => ''
            ], JSON_THROW_ON_ERROR)
        ));

        $whoAmI = $this->api->whoami();

        self::assertEquals($whoAmI->Identifier, '12345');
        self::assertEquals($whoAmI->FirstName, '');
        self::assertEquals($whoAmI->LastName, '');
        self::assertEquals($whoAmI->UniqueName, '');
        self::assertEquals($whoAmI->ProfileIdentifier, '');
        self::assertEquals($whoAmI->Pronouns, '');
    }


    /**
     * @return void
     */
    public function testBadRequestException(): void
    {
        $this->setResponse(new Response(400));
        $this->expectException(BadRequestException::class);
        $this->api->whoami();
        self::fail();
    }


    /**
     * @return void
     */
    public function testForbiddenException(): void
    {
        $this->setResponse(new Response(403));
        $this->expectException(ForbiddenException::class);
        $this->api->whoami();
        self::fail();
    }


    /**
     * @return void
     */
    public function testNotFoundException(): void
    {
        $this->setResponse(new Response(404));
        $this->expectException(NotFoundException::class);
        $this->api->whoami();
        self::fail();
    }


    /**
     * @return void
     */
    public function testTooManyRequestsException(): void
    {
        $this->setResponse(new Response(429));
        $this->expectException(TooManyRequestsException::class);
        $this->api->whoami();
        self::fail();
    }
}
