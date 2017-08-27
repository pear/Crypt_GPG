<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key import tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit ImportKeyTestCase
 * </code>
 *
 * LICENSE:
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/>
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * Tests key import abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class ImportKeyTestCase extends Crypt_GPG_TestCase
{
    // set up
    // {{{ setUp()

    public function setUp()
    {
        parent::setUp();

        // In GnuPG 2.1 first operation on a keyring in v1 format
        // will cause format update and several IMPORT_OK responses
        // This way we clean the state first
        $this->gpg->getKeys();
    }

    // }}}
    // {{{ testImportKey_private()

    /**
     * @group string
     */
    public function testImportKey_private()
    {
        // Note: Some of GnuPG 2.1.x versions return different private_imported
        // and private_uchanged values, bug? GnuPG 2.1.15 returns 1 as expected.

        $expectedResult = array(
            'fingerprint'       => 'F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB',
            'fingerprints'      => array('F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB'),
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        // {{{ private key data
        $privateKeyData = <<<TEXT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

lQHhBEjS+OIRBACPl023p+jInWiUtc7zSBU1D4mv42zSOwPdC37Pn/4x9FyhIOXE
LCRTpsnAw9rT6R3BvAC4uO68fxjxFCwTpsa60RsHw4bwpSAYuf0t5Xg+GQIritlm
XHVYwku3Hkh4Svv0quemooGuJ9lLwIHacL/4W1dTHLB2rzon0T4kx7ExZwCg/XKl
RD9zbbnQOgjn0EaS8fcSm+ED/1IMfkCz5ac9Y3jBUlcArOZcOlTrzxst+iMZm4f0
fh8dFCCaRN0iaVLSdCNaFvbKbJYZad1w3jFAMU9bX83flqgV1wMPO/NenfMidBIq
sKzgttaQo5VmjWPtwyOJXODR2lHKQR2hFCkIKlHMPLV3awCGV8iTyiTZMJirdtvf
s26oA/9STYro+yB9yrHufdfjM1u8SbSIhK6jUoq2ajLPHaLF2nRZZyv1gnkzRFd+
/Vxcx6cwp8Qd6L4z+0sU3pMS4X8rt2vqilK2msg1VrHnjGgFIfmfIvY5EmrhNzEx
6X82fbR9f8lwLy5N/gPm326e0xSw1rWdR15VukJPbmK6nf/pL/4DAwIZF3WLmXaM
DGCHa6b36T1VZ+bgYYcoQUanh3OSfLO0NwJ5ywFiML26DYZ7M3aivlfXj/8lOKy0
8tcg/rRcUHVibGljIE9ubHkgVGVzdCBLZXkgKGRvIG5vdCBlbmNyeXB0IGltcG9y
dGFudCBkYXRhIHdpdGggdGhpcyBrZXkpIDxwdWJsaWMtb25seUBleGFtcGxlLmNv
bT6IYAQTEQIAIAUCSNL44gIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEKuo
HvVOjA3r8DYAn1/DrF5jw31P3L6MlWdelLuR4POnAJ9It7IynfJalYIHoAWtY2xk
kTsT+p0CYgRI0vjoEAgAp65R578Es8qtASDAgIbYfJlJTwMovEnA4KJ69mpVt3mz
cFWMtJCvuilvwSQQ+VfKxjemtbe/IbMe9ssj4nTSLw/mweUB89tRj8ZzaS+/9312
AS8ra/xIDr6kTSfKcRKjXgMzkJ+A13rYwG5LFWnyumg36xglmzXKhecEkRVPfWn3
ISoq3zirZlQOWcKYdyA2Z685SKJC/N+3nUqKOJ7qrA7eT608LFksytBHeOfNf5m7
CC4wAE3RAz+ZkJvWRbE2G5pUalZktq8uKMT5WQgvuFP3hnvku5yilpo2ELTnYkO3
ltc3NHCc9v+jhikayPr7RvUdVPbaITT80yYKBPygCwADBggApzR1vW/fvzmrO5pW
zAvd4umVh/Yp34n3vWyXMu+JIHA7s08rkTzlMXzamICQmkjwAuCwJt0t7BA28Lny
goh2joxo8tE/OowFk+IzbeA2Vrz71d/T5SMDtC2mePE0m3bmCOLBscu5aJIfgi1X
/fzr44f4i+6hqVDCuOOmnVtbL4xBBnS6KXdcWP7QbVhxG3SpH9Agd/QXvSQm0Obz
9iKZ11FEXzgnVZGXaCM0GBsFE9JuNY5+hi6A72rccjhC0V1Cy43veeIhOE+v3pK0
a/BGUlgDSdgVopE9zUSQwzuo87UbY3EoDWBqDRSRCRMfmv8S2b9VJIRPdCOHZGCI
R49/0f4DAwIZF3WLmXaMDGCvSMKxFAt3zGZVEsfwS67ilWw0kq9wgmDpTmbrz1pe
8tUgmHxgiVc3Xo86ItXGr69udzSODYw2wO6JGdgOKsZDKAv7zJHi+3GISAQYEQIA
CQUCSNL46AIbDAAKCRCrqB71TowN6zbAAJ4qBrdmAYuAbY5txsc+Tmv9quOpzwCW
NN5B7Vl2JdxBuwWJrdfUb9UQzw==
=51qc
-----END PGP PRIVATE KEY BLOCK-----

TEXT;
        // }}}

        $result = $this->gpg->importKey($privateKeyData);
        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKey_public()

    /**
     * @group string
     */
    public function testImportKey_public()
    {
        $expectedResult = array(
            'fingerprint'       => '948F9835FF09F5F91CFF2AC1268AB7103435E65D',
            'fingerprints'      => array('948F9835FF09F5F91CFF2AC1268AB7103435E65D'),
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        // {{{ public key data
        $publicKeyData = <<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

mQGiBEjS+PgRBADbDdRN9iwESSyJvjnfgk7ZWUYKdHdSER7yJ0aM4LQjVDdw9y/f
QGidipXxVD2lW28gRtzcmLufxv3DzjZp83VaXvlJs9jbTtHDIYFyDW9kH1HTRbZT
WKWfuInd0AXzHy5o77qQ+mW0AIXbyke5suSHdvcmv1hiWI9OnXcIHpmavwCgt4Hm
+j3FpRo9qs4fJM887c796qUD/iPkStU9sM/0KCJFZNaPCGBaamCEi7UoAHNlim+B
dv3rfSQ2VcDRq9/3GoCEJ2c62XpgQxt79mojJLdWZsTWvr6ESnWOm7W6GIjv/Zc3
+OXgi7QdH5nwpZl6kBMkuzZxczFuwh9dqlXml+bND0JawS38MvQpDUkwMb592v5U
i9WIBADBacg6nixiTR+4kaHFE1Ww8QxT+vQ4S1SOx47cm8R6FxTRQA7FvK+vMxCt
Ps9GOzhjrCgIoF/6X10IZ7qB5jCYIH+kvHrp90ZbNwJ4pIa7phCPhqUF9mEyMbC2
AEIGp/Aw26yXKskQJJ3vFji+VaeCui21sXjg5EHfoayt79xT8bRfRXh0ZXJuYWwg
UHVibGljIEtleSAoZG8gbm90IGVuY3J5cHQgaW1wb3J0YW50IGRhdGEgd2l0aCB0
aGlzIGtleSkgPGV4dGVybmFsLXB1YmxpY0BleGFtcGxlLmNvbT6IYAQTEQIAIAUC
SNL4+AIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJECaKtxA0NeZdqHwAn3AF
EEhX1Tyba0ovCV2DwUytKM0CAKCnu6VzRy1Y8jp9fiy3ScwmaCI3FbkCDQRI0vj8
EAgArBRh0YpPhE1vvKoPuhGDa//96YqrYt9rmBo3AR1WmF3CKtspjXdOK2bCqdJh
H6kaoNi+0Ors00n2NfPj9Am2cTV3h2/KpAWOxQGfkmpzU3xXTVCUo/HoKDXIfWqk
/TPXRqbwFV489GRBtVov4IoZM0KqZXhaFD6cXBsEl/BVSvVdBqmBzUoJ2bOzYiSW
eg/ml65jbtxjDYMbxTLi7xRcTSAsareoN6/PcbAvcCE5UeCMu8p52wxHOTrAkI4/
6elpziVpIGn07zJb//4qIoZdhIzwfsMl73tPfdoL9jEC66SiWAN+BEDxceGR5E15
2WsT5tkxuz/pQUC1L3JW4WCC/wADBwf8CsevcPsk2XxT2XZj0lfmAOuhXxuqBczW
TXCimnRxvC8+uAacv1RgVRH6emW3BVjt0dr9vwRT0n54JA+7ZwXVMOo4/tqNwmJs
C6SThBXGBQxEaZwv19WC58DjblbvYa81cUaXrUdHi1OyoHwgalx0xZQ57IUXW6+7
qdLRfzyqbDBph9ogB0ta3AhSikAqqYImTrI650v/KWBLjrI+N925r0TvnfSOsru7
JrftccY2LntVnQUcXjuaFViZ7y8ocW8f92zmGj2zUN8z2GsMKiGQtNNmoX51TcQl
sJPsZF0RKduVkNUQa9cfzSIMjjhUSzspA2qHLUKafrS3e38s2Y4CNIhJBBgRAgAJ
BQJI0vj8AhsMAAoJECaKtxA0NeZdOFQAn15X+eYzFgVERrFkddsHvAE00OnSAJ9h
A7Lcv7M+9WeZ6cjeHkZfLB6LLA==
=AV/P
-----END PGP PUBLIC KEY BLOCK-----

TEXT;
        // }}}

        $result = $this->gpg->importKey($publicKeyData);
        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyAlreadyImported_private()

    /**
     * @group string
     */
    public function testImportKeyAlreadyImported_private()
    {
        // {{{ private key data
        $privateKeyData = <<<TEXT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

lQHhBEjS+OIRBACPl023p+jInWiUtc7zSBU1D4mv42zSOwPdC37Pn/4x9FyhIOXE
LCRTpsnAw9rT6R3BvAC4uO68fxjxFCwTpsa60RsHw4bwpSAYuf0t5Xg+GQIritlm
XHVYwku3Hkh4Svv0quemooGuJ9lLwIHacL/4W1dTHLB2rzon0T4kx7ExZwCg/XKl
RD9zbbnQOgjn0EaS8fcSm+ED/1IMfkCz5ac9Y3jBUlcArOZcOlTrzxst+iMZm4f0
fh8dFCCaRN0iaVLSdCNaFvbKbJYZad1w3jFAMU9bX83flqgV1wMPO/NenfMidBIq
sKzgttaQo5VmjWPtwyOJXODR2lHKQR2hFCkIKlHMPLV3awCGV8iTyiTZMJirdtvf
s26oA/9STYro+yB9yrHufdfjM1u8SbSIhK6jUoq2ajLPHaLF2nRZZyv1gnkzRFd+
/Vxcx6cwp8Qd6L4z+0sU3pMS4X8rt2vqilK2msg1VrHnjGgFIfmfIvY5EmrhNzEx
6X82fbR9f8lwLy5N/gPm326e0xSw1rWdR15VukJPbmK6nf/pL/4DAwIZF3WLmXaM
DGCHa6b36T1VZ+bgYYcoQUanh3OSfLO0NwJ5ywFiML26DYZ7M3aivlfXj/8lOKy0
8tcg/rRcUHVibGljIE9ubHkgVGVzdCBLZXkgKGRvIG5vdCBlbmNyeXB0IGltcG9y
dGFudCBkYXRhIHdpdGggdGhpcyBrZXkpIDxwdWJsaWMtb25seUBleGFtcGxlLmNv
bT6IYAQTEQIAIAUCSNL44gIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEKuo
HvVOjA3r8DYAn1/DrF5jw31P3L6MlWdelLuR4POnAJ9It7IynfJalYIHoAWtY2xk
kTsT+p0CYgRI0vjoEAgAp65R578Es8qtASDAgIbYfJlJTwMovEnA4KJ69mpVt3mz
cFWMtJCvuilvwSQQ+VfKxjemtbe/IbMe9ssj4nTSLw/mweUB89tRj8ZzaS+/9312
AS8ra/xIDr6kTSfKcRKjXgMzkJ+A13rYwG5LFWnyumg36xglmzXKhecEkRVPfWn3
ISoq3zirZlQOWcKYdyA2Z685SKJC/N+3nUqKOJ7qrA7eT608LFksytBHeOfNf5m7
CC4wAE3RAz+ZkJvWRbE2G5pUalZktq8uKMT5WQgvuFP3hnvku5yilpo2ELTnYkO3
ltc3NHCc9v+jhikayPr7RvUdVPbaITT80yYKBPygCwADBggApzR1vW/fvzmrO5pW
zAvd4umVh/Yp34n3vWyXMu+JIHA7s08rkTzlMXzamICQmkjwAuCwJt0t7BA28Lny
goh2joxo8tE/OowFk+IzbeA2Vrz71d/T5SMDtC2mePE0m3bmCOLBscu5aJIfgi1X
/fzr44f4i+6hqVDCuOOmnVtbL4xBBnS6KXdcWP7QbVhxG3SpH9Agd/QXvSQm0Obz
9iKZ11FEXzgnVZGXaCM0GBsFE9JuNY5+hi6A72rccjhC0V1Cy43veeIhOE+v3pK0
a/BGUlgDSdgVopE9zUSQwzuo87UbY3EoDWBqDRSRCRMfmv8S2b9VJIRPdCOHZGCI
R49/0f4DAwIZF3WLmXaMDGCvSMKxFAt3zGZVEsfwS67ilWw0kq9wgmDpTmbrz1pe
8tUgmHxgiVc3Xo86ItXGr69udzSODYw2wO6JGdgOKsZDKAv7zJHi+3GISAQYEQIA
CQUCSNL46AIbDAAKCRCrqB71TowN6zbAAJ4qBrdmAYuAbY5txsc+Tmv9quOpzwCW
NN5B7Vl2JdxBuwWJrdfUb9UQzw==
=51qc
-----END PGP PRIVATE KEY BLOCK-----

TEXT;
        // }}}

        $result = $this->gpg->importKey($privateKeyData);

        $expectedResult = array(
            'fingerprint'       => 'F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB',
            'fingerprints'      => array('F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB'),
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);

        $result = $this->gpg->importKey($privateKeyData);

        $expectedResult = array(
            'fingerprint'       => 'F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB',
            'fingerprints'      => array('F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB'),
            'public_imported'   => 0,
            'public_unchanged'  => version_compare($this->gpg->getVersion(), '2.1.0', 'ge') ? 1 : 0,
            'private_imported'  => 0,
            'private_unchanged'  => 1,
        );

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyAlreadyImported_public()

    /**
     * @group string
     */
    public function testImportKeyAlreadyImported_public()
    {
        // {{{ public key data
        $publicKeyData = <<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

mQGiBEjS+PgRBADbDdRN9iwESSyJvjnfgk7ZWUYKdHdSER7yJ0aM4LQjVDdw9y/f
QGidipXxVD2lW28gRtzcmLufxv3DzjZp83VaXvlJs9jbTtHDIYFyDW9kH1HTRbZT
WKWfuInd0AXzHy5o77qQ+mW0AIXbyke5suSHdvcmv1hiWI9OnXcIHpmavwCgt4Hm
+j3FpRo9qs4fJM887c796qUD/iPkStU9sM/0KCJFZNaPCGBaamCEi7UoAHNlim+B
dv3rfSQ2VcDRq9/3GoCEJ2c62XpgQxt79mojJLdWZsTWvr6ESnWOm7W6GIjv/Zc3
+OXgi7QdH5nwpZl6kBMkuzZxczFuwh9dqlXml+bND0JawS38MvQpDUkwMb592v5U
i9WIBADBacg6nixiTR+4kaHFE1Ww8QxT+vQ4S1SOx47cm8R6FxTRQA7FvK+vMxCt
Ps9GOzhjrCgIoF/6X10IZ7qB5jCYIH+kvHrp90ZbNwJ4pIa7phCPhqUF9mEyMbC2
AEIGp/Aw26yXKskQJJ3vFji+VaeCui21sXjg5EHfoayt79xT8bRfRXh0ZXJuYWwg
UHVibGljIEtleSAoZG8gbm90IGVuY3J5cHQgaW1wb3J0YW50IGRhdGEgd2l0aCB0
aGlzIGtleSkgPGV4dGVybmFsLXB1YmxpY0BleGFtcGxlLmNvbT6IYAQTEQIAIAUC
SNL4+AIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJECaKtxA0NeZdqHwAn3AF
EEhX1Tyba0ovCV2DwUytKM0CAKCnu6VzRy1Y8jp9fiy3ScwmaCI3FbkCDQRI0vj8
EAgArBRh0YpPhE1vvKoPuhGDa//96YqrYt9rmBo3AR1WmF3CKtspjXdOK2bCqdJh
H6kaoNi+0Ors00n2NfPj9Am2cTV3h2/KpAWOxQGfkmpzU3xXTVCUo/HoKDXIfWqk
/TPXRqbwFV489GRBtVov4IoZM0KqZXhaFD6cXBsEl/BVSvVdBqmBzUoJ2bOzYiSW
eg/ml65jbtxjDYMbxTLi7xRcTSAsareoN6/PcbAvcCE5UeCMu8p52wxHOTrAkI4/
6elpziVpIGn07zJb//4qIoZdhIzwfsMl73tPfdoL9jEC66SiWAN+BEDxceGR5E15
2WsT5tkxuz/pQUC1L3JW4WCC/wADBwf8CsevcPsk2XxT2XZj0lfmAOuhXxuqBczW
TXCimnRxvC8+uAacv1RgVRH6emW3BVjt0dr9vwRT0n54JA+7ZwXVMOo4/tqNwmJs
C6SThBXGBQxEaZwv19WC58DjblbvYa81cUaXrUdHi1OyoHwgalx0xZQ57IUXW6+7
qdLRfzyqbDBph9ogB0ta3AhSikAqqYImTrI650v/KWBLjrI+N925r0TvnfSOsru7
JrftccY2LntVnQUcXjuaFViZ7y8ocW8f92zmGj2zUN8z2GsMKiGQtNNmoX51TcQl
sJPsZF0RKduVkNUQa9cfzSIMjjhUSzspA2qHLUKafrS3e38s2Y4CNIhJBBgRAgAJ
BQJI0vj8AhsMAAoJECaKtxA0NeZdOFQAn15X+eYzFgVERrFkddsHvAE00OnSAJ9h
A7Lcv7M+9WeZ6cjeHkZfLB6LLA==
=AV/P
-----END PGP PUBLIC KEY BLOCK-----

TEXT;
        // }}}

        $result = $this->gpg->importKey($publicKeyData);

        $expectedResult = array(
            'fingerprint'       => '948F9835FF09F5F91CFF2AC1268AB7103435E65D',
            'fingerprints'      => array('948F9835FF09F5F91CFF2AC1268AB7103435E65D'),
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);

        $result = $this->gpg->importKey($publicKeyData);

        $expectedResult = array(
            'fingerprint'       => '948F9835FF09F5F91CFF2AC1268AB7103435E65D',
            'fingerprints'      => array('948F9835FF09F5F91CFF2AC1268AB7103435E65D'),
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyNoDataException_invalid()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testImportKeyNoDataException_invalid()
    {
        $keyData = 'Invalid OpenPGP data.';
        $this->gpg->importKey($keyData);
    }

    // }}}
    // {{{ testImportKeyNoDataException_empty()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testImportKeyNoDataException_empty()
    {
        $keyData = '';
        $this->gpg->importKey($keyData);
    }

    // }}}
    // {{{ testImportKeyFile_private()

    /**
     * @group file
     */
    public function testImportKeyFile_private()
    {
        $expectedResult = array(
            'fingerprint'       => 'F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB',
            'fingerprints'      => array('F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB'),
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        $filename = $this->getDataFilename('testImportKeyFile_private.asc');
        $result   = $this->gpg->importKeyFile($filename);

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyFile_public()

    /**
     * @group file
     */
    public function testImportKeyFile_public()
    {
        $expectedResult = array(
            'fingerprint'       => '948F9835FF09F5F91CFF2AC1268AB7103435E65D',
            'fingerprints'      => array('948F9835FF09F5F91CFF2AC1268AB7103435E65D'),
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $filename = $this->getDataFilename('testImportKeyFile_public.asc');
        $result   = $this->gpg->importKeyFile($filename);

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyFileAlreadyImported_private()

    /**
     * @group file
     */
    public function testImportKeyFileAlreadyImported_private()
    {
        $filename = $this->getDataFilename('testImportKeyFile_private.asc');
        $result   = $this->gpg->importKeyFile($filename);

        $expectedResult = array(
            'fingerprint'       => 'F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB',
            'fingerprints'      => array('F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB'),
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);

        $result = $this->gpg->importKeyFile($filename);

        $expectedResult = array(
            'fingerprint'       => 'F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB',
            'fingerprints'      => array('F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB'),
            'public_imported'   => 0,
            'public_unchanged'  => version_compare($this->gpg->getVersion(), '2.1.0', 'ge') ? 1 : 0,
            'private_imported'  => 0,
            'private_unchanged'  => 1,
        );

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyFileAlreadyImported_public()

    /**
     * @group file
     */
    public function testImportKeyFileAlreadyImported_public()
    {
        $filename = $this->getDataFilename('testImportKeyFile_public.asc');
        $result = $this->gpg->importKeyFile($filename);

        $expectedResult = array(
            'fingerprint'       => '948F9835FF09F5F91CFF2AC1268AB7103435E65D',
            'fingerprints'      => array('948F9835FF09F5F91CFF2AC1268AB7103435E65D'),
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);

        $result = $this->gpg->importKeyFile($filename);

        $expectedResult = array(
            'fingerprint'       => '948F9835FF09F5F91CFF2AC1268AB7103435E65D',
            'fingerprints'      => array('948F9835FF09F5F91CFF2AC1268AB7103435E65D'),
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyFileFileException()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testImportKeyFileFileException()
    {
        // input file does not exist
        $filename =
            $this->getDataFilename('testImportKeyFileFileException.asc');

        $this->gpg->importKeyFile($filename);
    }

    // }}}
    // {{{ testImportKeyFileNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group file
     */
    public function testImportKeyFileNoDataException()
    {
        $filename = $this->getDataFilename('testFileEmpty.plain');
        $this->gpg->importKeyFile($filename);
    }

    // }}}
}

?>
