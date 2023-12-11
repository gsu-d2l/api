<?php

declare(strict_types=1);

namespace GSU\D2L\API\DataHub;

use GSU\D2L\API\Core\Model\ObjectListPage;
use GSU\D2L\API\Core\D2LAPIClient;
use GSU\D2L\API\DataHub\Model\BDSExtractInfo;
use GSU\D2L\API\DataHub\Model\BDSInfo;
use mjfklib\HttpClient\Exception\HttpException;
use mjfklib\HttpClient\HttpClientMethods;

class DataHubAPI extends D2LAPIClient
{
    /**
     * @return BDSInfo[]
     */
    public function getBDS(): array
    {
        $bds = [];
        $bdsInfoNext = null;

        do {
            $bdsInfoList = $this->getBDSInfo($bdsInfoNext);
            $bdsInfoNext = $bdsInfoList->Next;

            foreach ($bdsInfoList->Objects as $bdsInfo) {
                $bdsExtractNext = null;

                do {
                    $bdsExtractList = $this->getBDSExtracts($bdsInfo->SchemaId, null, $bdsExtractNext);
                    $bdsExtractNext = $bdsExtractList->Next;

                    foreach ($bdsExtractList->Objects as $bdsExtract) {
                        $createdDate = $bdsExtract->CreatedDate->format(\DateTimeInterface::ATOM);
                        switch ($bdsExtract->BdsType) {
                            case 'Full':
                                if ($bdsInfo->Full !== null) {
                                    $bdsInfo->Full->Extracts[$createdDate] = $bdsExtract;
                                }
                                break;
                            case 'Differential':
                                if ($bdsInfo->Differential !== null) {
                                    $bdsInfo->Differential->Extracts[$createdDate] = $bdsExtract;
                                }
                                break;
                        }
                    }
                } while (is_string($bdsExtractNext));

                if ($bdsInfo->Full !== null) {
                    ksort($bdsInfo->Full->Extracts);
                }
                if ($bdsInfo->Differential !== null) {
                    ksort($bdsInfo->Differential->Extracts);
                }

                $bds[$bdsInfo->Name] = $bdsInfo;
            }
        } while (is_string($bdsInfoNext));

        ksort($bds);

        return $bds;
    }


    /**
     * @param string|null $next
     * @return ObjectListPage<BDSInfo>
     */
    public function getBDSInfo(?string $next = null): ObjectListPage
    {
        /** @var ObjectListPage<BDSInfo> */
        return ObjectListPage::create(
            $this->getResponseValues(
                $this->sendRequest(
                    $this->createRequest(
                        'GET',
                        $next ?? $this->config->d2lLPPrefix . "/datasets/bds"
                    ),
                    [200]
                )
            ),
            fn ($v) => BDSInfo::create($v)
        );
    }


    /**
     * @param string $schemaId
     * @param string|null $pluginId
     * @param string|null $next
     * @return ObjectListPage<BDSExtractInfo>
     */
    public function getBDSExtracts(
        string $schemaId,
        ?string $pluginId = null,
        ?string $next = null
    ): ObjectListPage {
        /** @var ObjectListPage<BDSExtractInfo> */
        return ObjectListPage::create(
            $this->getResponseValues(
                $this->sendRequest(
                    $this->createRequest(
                        'GET',
                        $next ?? $this->config->d2lLPPrefix . (
                            ($pluginId !== null)
                            ? "/datasets/bds/{$schemaId}/plugins/{$pluginId}/extracts"
                            : "/datasets/bds/{$schemaId}/extracts"
                        )
                    ),
                    [200]
                )
            ),
            fn ($v) => BDSExtractInfo::create($v)
        );
    }


    /**
     * @param BDSExtractInfo $extract
     * @param string $downloadPath
     * @return int
     */
    public function downloadBDSExtract(
        BDSExtractInfo $extract,
        string $downloadPath
    ): int {
        $requestCount = 0;
        $url = $extract->DownloadLink;

        try {
            do {
                $response = $this->sendRequest(
                    $this->createRequest('GET', $url),
                    [200, 302]
                );
                $url = ($response->getStatusCode() === 302) ? ($response->getHeader('Location')[0] ?? null) : null;
            } while (is_string($url) && ++$requestCount <= 5);
        } catch (HttpException $httpEx) {
            var_dump(
                $httpEx->request->getUri(),
                $httpEx->request->getHeaders()
            );

            throw new \RuntimeException(
                "Unable to download extract, count => {$requestCount}",
                0,
                $httpEx
            );
        }

        return HttpClientMethods::writeResponseToFile($response, $downloadPath);
    }
}
