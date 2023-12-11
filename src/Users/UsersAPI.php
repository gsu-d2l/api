<?php

declare(strict_types=1);

namespace GSU\D2L\API\Users;

use GSU\D2L\API\Core\Model\PagedResultSet;
use GSU\D2L\API\Core\D2LAPIClient;
use GSU\D2L\API\Users\Model\CreateUserData;
use GSU\D2L\API\Users\Model\UpdateUserData;
use GSU\D2L\API\Users\Model\UserData;
use GSU\D2L\API\Users\Model\WhoAmIUser;

class UsersAPI extends D2LAPIClient
{
    /**
     * @return WhoAmIUser
     */
    public function whoami(): WhoAmIUser
    {
        return WhoAmIUser::create(
            $this->getResponseValues(
                $this->sendRequest(
                    $this->createRequest(
                        'GET',
                        $this->config->d2lLPPrefix . "/users/whoami"
                    ),
                    200
                )
            )
        );
    }


    /**
     * @param string|null $orgDefinedId Org-defined identifier to look for
     * @param string|null $userName User name to look for
     * @param string|null $externalEmail External email address to look for
     * @param string|null $bookmark Bookmark to use for fetching next data set segment
     * @return UserData|UserData[]|PagedResultSet<UserData>|null
     */
    public function getUsers(
        ?string $orgDefinedId = null,
        ?string $userName = null,
        ?string $externalEmail = null,
        ?string $bookmark = null
    ): UserData|array|PagedResultSet|null {
        $responseType = match (true) {
            ($orgDefinedId !== null) => 'UserData[]',
            ($userName !== null) => 'UserData|null',
            ($externalEmail !== null) => 'UserData[]',
            default => 'PagedResultSet'
        };

        $response = $this->sendRequest(
            $this->createRequest(
                'GET',
                self::buildURL(
                    $this->config->d2lLPPrefix . "/users/",
                    [
                        'orgDefinedId' => $orgDefinedId,
                        'userName' => $userName,
                        'externalEmail' => $externalEmail,
                        'bookmark' => $bookmark
                    ]
                )
            ),
            [200, 404]
        );

        if ($response->getStatusCode() === 404) {
            /** @var UserData[]|PagedResultSet<UserData>|null */
            return match ($responseType) {
                'UserData|null' => null,
                'UserData[]' => [],
                'PagedResultSet' => PagedResultSet::create([
                    'PagingInfo' => [
                        'Bookmark' => '',
                        'HasMoreRecords' => false
                    ],
                    'Items' => []
                ], fn ($v) => UserData::create($v))
            };
        }

        $responseValues = $this->getResponseValues($response);

        /** @var UserData|UserData[]|PagedResultSet<UserData>|null */
        return match ($responseType) {
            'UserData|null' => UserData::create($responseValues),
            'UserData[]' => array_map(
                fn ($v) => UserData::create($v),
                $responseValues
            ),
            'PagedResultSet' => PagedResultSet::create(
                $responseValues,
                fn ($v) => UserData::create($v)
            )
        };
    }


    /**
     * @param int $userId
     * @return UserData
     */
    public function getUser(int $userId): UserData|null
    {
        $response = $this->sendRequest(
            $this->createRequest(
                'GET',
                $this->config->d2lLPPrefix . "/users/{$userId}"
            ),
            [200, 404]
        );

        if ($response->getStatusCode() === 404) {
            return null;
        }

        return UserData::create($this->getResponseValues($response));
    }


    /**
     * @param CreateUserData $createUserData
     * @return UserData
     */
    public function createUser(CreateUserData $createUserData): UserData
    {
        $request = $this
            ->createRequest('POST', $this->config->d2lLPPrefix . "/users/")
            ->withHeader('Content-Type', 'application/json');
        $request->getBody()->write(json_encode($createUserData, JSON_THROW_ON_ERROR));

        $response = $this->sendRequest($request, [200]);

        return UserData::create($this->getResponseValues($response));
    }


    /**
     * @param int $userId
     * @param UpdateUserData $updateUserData
     * @return UserData
     */
    public function updateUser(
        int $userId,
        UpdateUserData $updateUserData
    ): UserData {
        $request = $this
            ->createRequest('PUT', $this->config->d2lLPPrefix . "/users/{$userId}")
            ->withHeader('Content-Type', 'application/json');
        $request->getBody()->write(json_encode($updateUserData, JSON_THROW_ON_ERROR));

        $response = $this->sendRequest($request, [200]);

        return UserData::create($this->getResponseValues($response));
    }


    /**
     * @param int $userId
     * @return void
     */
    public function deleteUser(int $userId): void
    {
        $this->sendRequest(
            $this->createRequest(
                'GET',
                $this->config->d2lLPPrefix . "/users/{$userId}"
            ),
            [200]
        );
    }
}
