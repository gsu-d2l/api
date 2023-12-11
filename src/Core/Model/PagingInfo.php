<?php

declare(strict_types=1);

namespace GSU\D2L\API\Core\Model;

use mjfklib\Utils\ArrayValue;

class PagingInfo
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            Bookmark: ArrayValue::getString($values, 'Bookmark'),
            HasMoreItems: ArrayValue::getBool($values, 'HasMoreItems')
        );
    }


    /**
     * @param string $Bookmark
     * @param bool $HasMoreItems
     */
    public function __construct(
        public string $Bookmark,
        public bool $HasMoreItems
    ) {
    }
}
