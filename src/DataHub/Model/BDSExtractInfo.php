<?php

declare(strict_types=1);

namespace GSU\D2L\API\DataHub\Model;

use mjfklib\Utils\ArrayValue;

class BDSExtractInfo implements \JsonSerializable
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            SchemaId: ArrayValue::getString($values, 'SchemaId'),
            PluginId: ArrayValue::getString($values, 'PluginId'),
            BdsType: ArrayValue::getString($values, 'BdsType'),
            CreatedDate: ArrayValue::getDateTime($values, 'CreatedDate'),
            DownloadSize: ArrayValue::getInt($values, 'DownloadSize'),
            DownloadLink: ArrayValue::getString($values, 'DownloadLink'),
            QueuedForProcessingDate: ArrayValue::getDateTime($values, 'QueuedForProcessingDate'),
            Version: ArrayValue::getString($values, 'Version'),
        );
    }


    /**
     * @param string $SchemaId
     * @param string $PluginId
     * @param string $BdsType
     * @param \DateTimeInterface $CreatedDate
     * @param int $DownloadSize
     * @param string $DownloadLink
     * @param \DateTimeInterface $QueuedForProcessingDate
     * @param string $Version
     */
    public function __construct(
        public readonly string $SchemaId,
        public readonly string $PluginId,
        public readonly string $BdsType,
        public readonly \DateTimeInterface $CreatedDate,
        public readonly int $DownloadSize,
        public readonly string $DownloadLink,
        public readonly \DateTimeInterface $QueuedForProcessingDate,
        public readonly string $Version
    ) {
    }


    /**
     * @return mixed
     */
    public function jsonSerialize(): mixed
    {
        $values = get_object_vars($this);
        $values['CreatedDate'] = $this->CreatedDate->format(\DateTimeInterface::ATOM);
        $values['QueuedForProcessingDate'] = $this->QueuedForProcessingDate->format(\DateTimeInterface::ATOM);
        return $values;
    }
}
