<?php

declare(strict_types=1);

namespace GSU\D2L\API\Core\Model;

use mjfklib\Utils\ArrayValue;

/**
 * @template T
 */
class ObjectListPage
{
    /**
     * @param mixed $values
     * @param (callable(mixed $v): T) $castObject
     * @return self<T>
     */
    public static function create(
        mixed $values,
        callable $castObject
    ): self {
        $values = ArrayValue::convertToArray($values);
        return new self(
            Next: ArrayValue::getStringNull($values, 'PagingInfo'),
            Objects: array_map(
                $castObject,
                ArrayValue::getArray($values, 'Objects')
            )
        );
    }


    /**
     * @param string|null $Next
     * @param T[] $Objects
     */
    public function __construct(
        public ?string $Next,
        public array $Objects
    ) {
    }
}
