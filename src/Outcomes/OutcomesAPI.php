<?php

declare(strict_types=1);

namespace GSU\D2L\API\Outcomes;

use GSU\D2L\API\Core\D2LAPIClient;
use GSU\D2L\API\Outcomes\Model\OutcomeDetails;
use GSU\D2L\API\Outcomes\Model\OutcomeDetailsImport;
use GSU\D2L\API\Outcomes\Model\OutcomeRegistry;

class OutcomesAPI extends D2LAPIClient
{
    public const LO_URL = 'https://lores-us-east-1.brightspace.com/api/lores/1.0/registries/';


    public function getRegistryId(int $orgUnitId): string
    {
        $url = "/d2l/le/lo/{$orgUnitId}/outcomes-management";

        $response = $this->sendRequest(
            $this->createRequest('GET', $url, true, false),
            [200]
        );

        $document = new \DOMDocument();
        if (!@$document->loadHTML($response->getBody()->getContents())) {
            throw new \RuntimeException("Unable to parse contents");
        }

        $d2lOutcomesManagement = $document->getElementsByTagName("d2l-outcomes-management")->item(0);
        if ($d2lOutcomesManagement === null) {
            throw new \RuntimeException("Element 'd2l-outcomes-management' not found");
        }

        $attrCount = $d2lOutcomesManagement->attributes?->length ?? 0;
        for ($i = 0; $i < $attrCount; $i++) {
            $attr = $d2lOutcomesManagement->attributes->item($i);
            if ($attr !== null && $attr->nodeName === 'registry-id' && is_string($attr->nodeValue)) {
                return $attr->nodeValue;
            }
        }

        throw new \RuntimeException("Attribute 'registry-id' not found");
    }


    /**
     * @param string $registryId
     * @return OutcomeRegistry
     */
    public function getRegistry(string $registryId): OutcomeRegistry
    {
        $request = $this->createRequest(
            'GET',
            self::LO_URL . $registryId,
            true
        );

        $response = $this->sendRequest(
            $request,
            [200]
        );

        return OutcomeRegistry::create(
            $this->getResponseValues($response)
        );
    }


    /**
     * @param string $registryId
     * @param OutcomeDetails[] $objectives
     * @return void
     */
    public function importObjectives(
        string $registryId,
        array $objectives
    ): void {
        $request = $this->createRequest('PUT', self::LO_URL . $registryId, true);
        $request = $request->withHeader('Content-Type', 'application/json');
        $request->getBody()->write(json_encode([
            'objectives' => array_map(
                fn ($v) => new OutcomeDetailsImport($v),
                array_values($objectives)
            )
        ], JSON_THROW_ON_ERROR));

        $this->sendRequest($request, [200]);
    }
}
