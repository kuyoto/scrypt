<?php

/**
 * kuyoto scrypt (https://github.com/kuyoto/scrypt/).
 *
 * PHP version 7
 *
 * @category  Library
 *
 * @author    Tolulope Kuyoro <nifskid1999@gmail.com>
 * @copyright 2020 Tolulope Kuyoro <nifskid1999@gmail.com>
 * @license   http://www.opensource.org/licenses/mit-license.php (MIT License)
 *
 * @see      https://github.com/kuyoto/scrypt/
 */

declare(strict_types=1);

namespace Kuyoto\Scrypt;

use PHPUnit\Framework\TestCase;

/**
 * Scrypt unit test.
 *
 * @category Library
 *
 * @author   Tolulope Kuyoro <nifskid1999@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php (MIT License)
 *
 * @see     https://github.com/kuyoto/scrypt/
 *
 * @internal
 * @coversNothing
 */
class ScryptTest extends TestCase
{
    /**
     * ScryptTest::testScrypt().
     *
     * @see https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01#section-11
     */
    public function testScrypt()
    {
        $expected1 = str_replace(
            ' ',
            '',
            '77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97'.
            'f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42'.
            'fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17'.
            'e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06'
        );

        $expected2 = str_replace(
            ' ',
            '',
            'fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe'.
            '7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62'.
            '2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da'.
            'c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40'
        );

        $expected3 = str_replace(
            ' ',
            '',
            '70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb'.
            'fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2'.
            'd5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9'.
            'e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87'
        );

        $expected4 = str_replace(
            ' ',
            '',
            '21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81'.
            'ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47'.
            '8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3'.
            '37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4'
        );

        $actual1 = Scrypt::calc('', '', 16, 1, 1, 64);
        $actual2 = Scrypt::calc('password', 'NaCl', 1024, 8, 16, 64);
        $actual3 = Scrypt::calc('pleaseletmein', 'SodiumChloride', 16384, 8, 1, 64);
        $actual4 = Scrypt::calc('pleaseletmein', 'SodiumChloride', 1048576, 8, 1, 64);

        $this->assertEquals($expected1, bin2hex($actual1));
        $this->assertEquals($expected2, bin2hex($actual2));
        $this->assertEquals($expected3, bin2hex($actual3));
        $this->assertEquals($expected4, bin2hex($actual4));
    }
}
