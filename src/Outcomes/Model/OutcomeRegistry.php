<?php

declare(strict_types=1);

namespace GSU\D2L\API\Outcomes\Model;

use mjfklib\Utils\ArrayValue;

class OutcomeRegistry
{
    /**
     * @param mixed $values
     * @return self
     */
    public static function create(mixed $values): self
    {
        $values = ArrayValue::convertToArray($values);
        return new self(
            id: ArrayValue::getString($values, 'id'),
            objectives: array_values(array_map(
                fn ($v) => OutcomeDetails::create($v),
                ArrayValue::getArrayNull($values, 'objectives') ?? []
            ))
        );
    }


    /**
     * @param string $id
     * @param array<int,OutcomeDetails> $objectives
     */
    public function __construct(
        public string $id,
        public array $objectives = []
    ) {
        $this->objectives = array_values($objectives);
    }


    /**
     * @param OutcomeRegistry $outcomeRegistry
     * @return static
     */
    public function merge(OutcomeRegistry $outcomeRegistry): static
    {
        $this->objectives = $this->mergeOutcomes(
            $outcomeRegistry->objectives,
            $this->objectives
        );

        return $this;
    }


    /**
     * @param array<int,OutcomeDetails> $source
     * @param array<int,OutcomeDetails> $target
     * @return array<int,OutcomeDetails>
     */
    private function mergeOutcomes(
        array $source,
        array $target
    ): array {
        // Build index on target
        /** @var array<string,int> $targetIdKeys */
        $targetIdKeys = array_column(
            array_map(
                fn (OutcomeDetails $v, int $k) => [$v->id, $k],
                $target,
                array_keys($target)
            ),
            0,
            1
        );

        foreach ($source as $sourceOutcome) {
            // Look for source outcome in target
            $targetOutcome = $target[$targetIdKeys[$sourceOutcome->id] ?? null] ?? null;

            if ($targetOutcome === null) {
                // If source does not exist in target, add to target
                $target[] = $sourceOutcome;
            } else {
                // If source does exist in target, merge sources's children into target's children
                $targetOutcome->children = $this->mergeOutcomes(
                    $sourceOutcome->children,
                    $targetOutcome->children
                );
            }
        }

        return $target;
    }
}
