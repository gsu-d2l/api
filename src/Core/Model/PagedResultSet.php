<?php

declare(strict_types=1);

namespace GSU\D2L\API\Core\Model;

use mjfklib\Utils\ArrayValue;

/**
 * @template T
 */
class PagedResultSet
{
    /**
     * @param mixed $values
     * @param (callable(mixed $v): T) $castItem
     * @return self<T>
     */
    public static function create(
        mixed $values,
        callable $castItem
    ): self {
        $values = ArrayValue::convertToArray($values);
        return new self(
            PagingInfo: PagingInfo::create(ArrayValue::getArray($values, 'PagingInfo')),
            Items: array_map(
                $castItem,
                ArrayValue::getArray($values, 'Items')
            )
        );
    }


    /**
     * @param PagingInfo $PagingInfo
     * @param T[] $Items
     */
    public function __construct(
        public PagingInfo $PagingInfo,
        public array $Items
    ) {
    }
}
