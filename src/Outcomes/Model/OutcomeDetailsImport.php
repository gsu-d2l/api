<?php

declare(strict_types=1);

namespace GSU\D2L\API\Outcomes\Model;

class OutcomeDetailsImport
{
    /** @var string $id*/
    public string $id;

    /** @var array<int,OutcomeDetailsImport> $children */
    public array $children;

    /**
     * @param OutcomeDetails $outcomeDetails
     */
    public function __construct(OutcomeDetails $outcomeDetails)
    {
        $this->id = $outcomeDetails->id;
        $this->children = array_map(
            fn ($v) => new OutcomeDetailsImport($v),
            $outcomeDetails->children
        );
    }
}
