<?php

declare(strict_types=1);

namespace GSU\D2L\API\Outcomes\Model;

use mjfklib\Utils\ArrayValue;

final class OutcomeRegistry
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
                fn($v) => OutcomeDetails::create($v),
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
     * @return self
     */
    public function merge(OutcomeRegistry $outcomeRegistry): self
    {
        $objectives = $this->mergeOutcomes(
            $outcomeRegistry->objectives,
            $this->objectives
        );

        return new self($this->id, $objectives);
    }


    /**
     * @param OutcomeRegistry $outcomeRegistry
     * @return bool
     */
    public function equals(OutcomeRegistry $outcomeRegistry): bool
    {
        return $this->compareOutcomes(
            $outcomeRegistry->objectives,
            $this->objectives
        );
    }


    /**
     * @param OutcomeDetails[] $source
     * @param OutcomeDetails[] $target
     * @return OutcomeDetails[]
     */
    private function mergeOutcomes(
        array $source,
        array $target
    ): array {
        /** @var array<string,OutcomeDetails> $source */
        $source = array_column(
            array_map(
                fn(OutcomeDetails $v) => [$v, $v->id],
                $source,
            ),
            0,
            1
        );

        /** @var array<string,OutcomeDetails> $target */
        $target = array_column(
            array_map(
                fn(OutcomeDetails $v) => [$v, $v->id],
                $target,
            ),
            0,
            1
        );

        foreach ($source as $id => $sourceOutcome) {
            // Look for source outcome in target
            $targetOutcome = $target[$id] ?? null;

            if ($targetOutcome === null) {
                // If source does not exist in target, add to target
                $target[$id] = $sourceOutcome;
            } else {
                // If source does exist in target, merge sources's children into target's children
                $targetOutcome->children = $this->mergeOutcomes(
                    $sourceOutcome->children,
                    $targetOutcome->children
                );
            }
        }

        return array_values($target);
    }


    /**
     * @param OutcomeDetails[] $source
     * @param OutcomeDetails[] $target
     * @return bool
     */
    private function compareOutcomes(
        array $source,
        array $target
    ): bool {
        /** @var array<string,OutcomeDetails> $source */
        $source = array_column(
            array_map(
                fn(OutcomeDetails $v) => [$v, $v->id],
                $source,
            ),
            0,
            1
        );

        /** @var array<string,OutcomeDetails> $target */
        $target = array_column(
            array_map(
                fn(OutcomeDetails $v) => [$v, $v->id],
                $target,
            ),
            0,
            1
        );

        if (count($source) !== count($target)) {
            return false;
        }

        foreach ($source as $id => $sourceOutcome) {
            $targetOutcome = $target[$id] ?? null;
            if (
                $targetOutcome === null ||
                !$this->compareOutcomes($sourceOutcome->children, $targetOutcome->children)
            ) {
                return false;
            }
        }

        return true;
    }
}
