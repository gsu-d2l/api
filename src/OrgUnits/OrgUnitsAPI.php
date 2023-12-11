<?php

declare(strict_types=1);

namespace GSU\D2L\API\OrgUnits;

use GSU\D2L\API\Core\D2LAPIClient;
use GSU\D2L\API\Core\Model\PagedResultSet;
use GSU\D2L\API\OrgUnits\Model\Organization;
use GSU\D2L\API\OrgUnits\Model\OrgUnit;
use GSU\D2L\API\OrgUnits\Model\OrgUnitTypeInfo;

class OrgUnitsAPI extends D2LAPIClient
{
    /**
     * @return Organization
     */
    public function getOrgInfo(): Organization
    {
        $request = $this->createRequest(
            'GET',
            $this->config->d2lLPPrefix . "/organization/info"
        );

        $response = $this->sendRequest(
            $request,
            [200]
        );

        return Organization::create(
            $this->getResponseValues($response)
        );
    }


    /**
     * @return OrgUnitTypeInfo[]
     */
    public function getOrgTypes(): array
    {
        $request = $this->createRequest(
            'GET',
            $this->config->d2lLPPrefix . "/outypes/"
        );

        $response = $this->sendRequest(
            $request,
            [200]
        );

        return array_map(
            fn ($v) => OrgUnitTypeInfo::create($v),
            $this->getResponseValues($response)
        );
    }


    /**
     * @param int $orgUnitId
     * @param int|null $ouTypeId
     * @return OrgUnit[]
     */
    public function getAncestors(int $orgUnitId, ?int $ouTypeId = null): array
    {
        $request = $this->createRequest(
            'GET',
            self::buildURL(
                $this->config->d2lLPPrefix . "/orgstructure/${orgUnitId}/ancestors/",
                [
                    'ouTypeId' => $ouTypeId,
                ]
            )
        );

        $response = $this->sendRequest(
            $request,
            [200]
        );

        return array_map(
            fn ($v) => OrgUnit::create($v),
            $this->getResponseValues($response)
        );
    }


    /**
     * @param int $orgUnitId
     * @param int $ouTypeId
     * @param string $bookmark
     * @return PagedResultSet<OrgUnit>
     */
    public function getDescendants(
        int $orgUnitId,
        ?int $ouTypeId = null,
        ?string $bookmark = null
    ): PagedResultSet {
        $request = $this->createRequest(
            'GET',
            self::buildURL(
                $this->config->d2lLPPrefix . "/orgstructure/${orgUnitId}/descendants/paged/",
                [
                    'ouTypeId' => $ouTypeId,
                    'bookmark' => $bookmark
                ]
            )
        );

        $response = $this->sendRequest(
            $request,
            [200]
        );

        /** @var PagedResultSet<OrgUnit> */
        return PagedResultSet::create(
            $this->getResponseValues($response),
            fn ($v) => OrgUnit::create($v)
        );
    }


    /**
     * @param int $orgUnitId
     * @param int $parentOrgUnitId
     * @return void
     */
    public function addParent(
        int $orgUnitId,
        int $parentOrgUnitId
    ): void {
        $request = $this
            ->createRequest('POST', $this->config->d2lLPPrefix . "/orgstructure/${orgUnitId}/parents/")
            ->withHeader("Content-Type", "application/json");
        $request->getBody()->write("{$parentOrgUnitId}");

        $this->sendRequest($request, [200]);
    }


    /**
     * @param int $orgUnitId
     * @param int $parentOrgUnitId
     * @return void
     */
    public function removeParent(
        int $orgUnitId,
        int $parentOrgUnitId
    ): void {
        $request = $this
            ->createRequest(
                'DELETE',
                $this->config->d2lLPPrefix . "/orgstructure/${orgUnitId}/parents/${parentOrgUnitId}"
            )
            ->withHeader("Content-Type", "application/json");
        $request->getBody()->write("{$parentOrgUnitId}");

        $this->sendRequest($request, [200]);
    }


    /**
     * @param int $orgUnitId
     * @param int $childOrgUnitId
     * @return void
     */
    public function addChild(
        int $orgUnitId,
        int $childOrgUnitId
    ): void {
        $request = $this
            ->createRequest('POST', $this->config->d2lLPPrefix . "/orgstructure/${orgUnitId}/children/")
            ->withHeader("Content-Type", "application/json");
        $request->getBody()->write("{$childOrgUnitId}");

        $this->sendRequest($request, [200]);
    }


    /**
     * @param int $orgUnitId
     * @param int $parentOrgUnitId
     * @return void
     */
    public function removeChild(
        int $orgUnitId,
        int $parentOrgUnitId
    ): void {
        $request = $this
            ->createRequest(
                'DELETE',
                $this->config->d2lLPPrefix . "/orgstructure/${orgUnitId}/children/${parentOrgUnitId}"
            )
            ->withHeader("Content-Type", "application/json");
        $request->getBody()->write("{$parentOrgUnitId}");

        $this->sendRequest($request, [200]);
    }
}
