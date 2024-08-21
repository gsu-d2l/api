<?php

declare(strict_types=1);

namespace GSU\D2L\API\Auth;

final class TOTP
{
    public static function getCounter(
        int|null $currentTime = null,
        int $startTime = 0,
        int $timePeriod = 30,
    ): int {
        $currentTime ??= time();
        return intval(floor(($currentTime - $startTime) / $timePeriod));
    }

    public static function getTimestamp(
        int $counter,
        int $startTime = 0,
        int $timePeriod = 30,
    ): int {
        return ($counter * $timePeriod) + $startTime;
    }

    public static function generateCode(
        string $key,
        int $counter,
        string $algo = 'sha1',
        int $length = 6,
    ): string {
        if (strlen($key) < 16) {
            throw new \LogicException('\$key must be at least 16 bytes');
        }
        if (preg_match('/[^a-z2-7]/i', $key) === 1) {
            throw new \LogicException('\$key must be base32-encoded');
        }
        if ($counter < 0) {
            throw new \LogicException('\$counter must be a positive integer: ' . $counter);
        }
        if ($length < 6 || $length > 10) {
            throw new \LogicException('\$length can only be a value between 6 and 10');
        }
        if (!in_array($algo, hash_hmac_algos(), true)) {
            throw new \LogicException('Not a supported hmac algorition: ' . $algo);
        }

        // Step 1: Generate an HMAC value
        $hash = hash_hmac(
            $algo,
            // unsigned long (always 32 bit, big endian byte order)
            str_pad(
                pack('N', $counter),
                8,
                "\x00",
                STR_PAD_LEFT
            ),
            Base32::decode($key)
        );

        // Step 2: Generate a 4-byte string (Dynamic Truncation)
        $offset = (int) hexdec(substr($hash, -1, 1)); // low-order 4 bits of last byte in $hash
        $extract = hexdec(substr($hash, 2 * $offset, 8)); // first 32 bits (4 bytes) from offset
        $truncate = $extract & 0x7fffffff; // first byte is masked with a 0x7f

        // Step 3: Compute an HOTP value
        $code = $truncate % pow(10, $length);

        return sprintf(
            "%1\$0{$length}d",
            $code
        );
    }
}
