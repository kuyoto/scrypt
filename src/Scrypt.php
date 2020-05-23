<?php

/**
 * kuyoto scrypt (https://github.com/kuyoto/scrypt/)
 *
 * PHP version 7
 *
 * @category  Library
 * @package   kuyoto\scrypt
 * @author    Tolulope Kuyoro <nifskid1999@gmail.com>
 * @copyright 2020 Tolulope Kuyoro <nifskid1999@gmail.com>
 * @license   http://www.opensource.org/licenses/mit-license.php (MIT License)
 * @version   GIT: master
 * @link      https://github.com/kuyoto/scrypt/
 */

declare(strict_types=1);

namespace Kuyoto\Scrypt;

/**
 * Scrypt key derivation function.
 *
 * @category Library
 * @package  kuyoto\scrypt
 * @author   Tolulope Kuyoro <nifskid1999@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php (MIT License)
 * @link     https://github.com/kuyoto/scrypt/
 * @see      http://www.tarsnap.com/scrypt.html
 * @see      https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01
 * @internal
 */
class Scrypt
{
    /**
     * Executes the scrypt algorithm.
     *
     * @param string $passwd The passphrase.
     * @param string $salt   The salt.
     * @param int    $n      The CPU/Memory cost parameter, must be larger than 1,
     *                       a power of 2 and less than 2^(128 * r / 8).
     * @param int    $r      The block size.
     * @param int    $p      The parallelization parameter, a positive integer less than
     *                       or equal to ((2^32-1) * hLen) / MFLen where hLen is 32 and MFlen is 128 * r.
     * @param int    $dklen  The length of the output key.
     *
     * @throws \ErrorException
     *
     * @return string The derives key of length dklen.
     */
    public static function calc(string $passwd, string $salt, int $n, int $r, int $p, int $dklen): string
    {
        if ($n == 0 || ($n & ($n - 1)) != 0) {
            throw new \ErrorException('N must be > 0 and a power of 2');
        }

        if ($n > PHP_INT_MAX / 128 / $r) {
            throw new \ErrorException('Parameter n is too large');
        }

        if ($r > PHP_INT_MAX / 128 / $p) {
            throw new \ErrorException('Parameter r is too large');
        }

        $b = hash_pbkdf2('sha256', $passwd, $salt, 1, $p * 128 * $r, true);

        $s = '';

        for ($i = 0; $i < $p; $i++) {
            $s .= self::scryptROMix(substr($b, $i * 128 * $r, 128 * $r), $n, $r);
        }

        return hash_pbkdf2('sha256', $passwd, $s, 1, $dklen, true);
    }

    /**
     * scryptROMix
     *
     * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-4
     *
     * @param string $b The input octet vector of length 128 * r octets.
     * @param int    $n The CPU/memory cost, must be larger than 1, a power of 2 and less than 2^(128 * r / 8).
     * @param int    $r The block size.
     *
     * @return string
     */
    private static function scryptROMix(string $b, int $n, int $r): string
    {
        $v = [];

        for ($i = 0; $i < $n; $i++) {
            $v[$i] = $b;
            $b     = self::scryptBlockMix($b, $r);
        }

        for ($i = 0; $i < $n; $i++) {
            $k = self::integrity($b);
            $t = $b ^ $v[$k % $n];
            $b = self::scryptBlockMix($t, $r);
        }

        return $b;
    }

    /**
     * scryptBlockMix
     *
     * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-3
     *
     * @param string $b The input vector of 2 * r 64-octet blocks.
     * @param int    $r The block size.
     *
     * @return string
     */
    private static function scryptBlockMix($b, int $r): string
    {
        $x    = substr($b, -64);
        $even = '';
        $odd  = '';
        $len  = 2 * $r;

        for ($i = 0; $i < $len; $i++) {
            $x = self::salsa208($x ^ substr($b, 64 * $i, 64));

            if ($i % 2 == 0) {
                $even .= $x;
            } else {
                $odd .= $x;
            }
        }
        return $even . $odd;
    }

    /**
     * Salsa 20/8 core (32 and 64 bit version)
     *
     * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-2
     * @see http://cr.yp.to/salsa20.html
     *
     * @param string $b
     *
     * @return string
     */
    private static function salsa208($b): string
    {
        $b32 = [];

        for ($i = 0; $i < 16; $i++) {
            list(, $b32[$i]) = unpack('V', substr($b, $i * 4, 4));
        }

        $x = $b32;

        for ($i = 0; $i < 8; $i += 2) {
            $x[4]  ^= self::rotate($x[0], $x[12], 7);
            $x[8]  ^= self::rotate($x[4], $x[0], 9);
            $x[12] ^= self::rotate($x[8], $x[4], 13);
            $x[0]  ^= self::rotate($x[12], $x[8], 18);
            $x[9]  ^= self::rotate($x[5], $x[1], 7);
            $x[13] ^= self::rotate($x[9], $x[5], 9);
            $x[1]  ^= self::rotate($x[13], $x[9], 13);
            $x[5]  ^= self::rotate($x[1], $x[13], 18);
            $x[14] ^= self::rotate($x[10], $x[6], 7);
            $x[2]  ^= self::rotate($x[14], $x[10], 9);
            $x[6]  ^= self::rotate($x[2], $x[14], 13);
            $x[10] ^= self::rotate($x[6], $x[2], 18);
            $x[3]  ^= self::rotate($x[15], $x[11], 7);
            $x[7]  ^= self::rotate($x[3], $x[15], 9);
            $x[11] ^= self::rotate($x[7], $x[3], 13);
            $x[15] ^= self::rotate($x[11], $x[7], 18);
            $x[1]  ^= self::rotate($x[0], $x[3], 7);
            $x[2]  ^= self::rotate($x[1], $x[0], 9);
            $x[3]  ^= self::rotate($x[2], $x[1], 13);
            $x[0]  ^= self::rotate($x[3], $x[2], 18);
            $x[6]  ^= self::rotate($x[5], $x[4], 7);
            $x[7]  ^= self::rotate($x[6], $x[5], 9);
            $x[4]  ^= self::rotate($x[7], $x[6], 13);
            $x[5]  ^= self::rotate($x[4], $x[7], 18);
            $x[11] ^= self::rotate($x[10], $x[9], 7);
            $x[8]  ^= self::rotate($x[11], $x[10], 9);
            $x[9]  ^= self::rotate($x[8], $x[11], 13);
            $x[10] ^= self::rotate($x[9], $x[8], 18);
            $x[12] ^= self::rotate($x[15], $x[14], 7);
            $x[13] ^= self::rotate($x[12], $x[15], 9);
            $x[14] ^= self::rotate($x[13], $x[12], 13);
            $x[15] ^= self::rotate($x[14], $x[13], 18);
        }

        for ($i = 0; $i < 16; $i++) {
            $t       = $b32[$i] + $x[$i];
            $b32[$i] = PHP_INT_SIZE === 4 ? $t : $t & 0xffffffff;
        }

        $result = '';

        for ($i = 0; $i < 16; $i++) {
            $result .= pack('V', $b32[$i]);
        }

        return $result;
    }

    /**
     * Rotates between a 32 and 64 bit version.
     *
     * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-2
     * @see http://cr.yp.to/salsa20.html
     *
     * @param int $x1
     * @param int $x2
     * @param int $1
     *
     * @return int
     */
    private static function rotate(int $x1, int $x2, int $i): int
    {
		// @codingStandardsIgnoreStart
        static $_mods   = [0x7f, 0x1ff, 0x1fff, 0x3ffff];
        static $_mods_i = 0;

		$d = ($x1 + $x2);

        if (PHP_INT_SIZE === 4) {
			$x       = ($d << $i) | ($d >> (32 - $i)) & $_mods[$_mods_i++];
            $_mods_i = $_mods_i === 3 ? 0 : $_mods_i;
        } else {
			$d &= 0xffffffff;
            $x  = ($d << $i) | ($d >> (32 - $i));
        }
		// @codingStandardsIgnoreEnd

        return $x;
    }

    /**
     * Integerify (B[0] ... B[2 * r - 1]) is defined as the result
     * of interpreting B[2 * r - 1] as a little-endian integer.
     * Each block B is a string of 64 bytes.
     *
     * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-4
     *
     * @param string $b
     *
     * @return int
     */
    private static function integrity(string $b): int
    {
        $v = PHP_INT_SIZE === 8 ? 'V' : 'v';

        list(, $k) = unpack($v, substr($b, -64));

        return $k;
    }
}
