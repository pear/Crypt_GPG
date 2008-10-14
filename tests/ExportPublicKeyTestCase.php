<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key export tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit ExportPublicKeyTestCase
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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
 * Tests key export abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class ExportPublicKeyTestCase extends Crypt_GPG_TestCase
{
    // {{{ testExportPublicKey()

    /**
     * @group export
     */
    public function testExportPublicKey()
    {
        $keyId = 'public-only@example.com';

        // {{{ expected key data
        $expectedKeyData = <<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

mQGiBEjS+OIRBACPl023p+jInWiUtc7zSBU1D4mv42zSOwPdC37Pn/4x9FyhIOXE
LCRTpsnAw9rT6R3BvAC4uO68fxjxFCwTpsa60RsHw4bwpSAYuf0t5Xg+GQIritlm
XHVYwku3Hkh4Svv0quemooGuJ9lLwIHacL/4W1dTHLB2rzon0T4kx7ExZwCg/XKl
RD9zbbnQOgjn0EaS8fcSm+ED/1IMfkCz5ac9Y3jBUlcArOZcOlTrzxst+iMZm4f0
fh8dFCCaRN0iaVLSdCNaFvbKbJYZad1w3jFAMU9bX83flqgV1wMPO/NenfMidBIq
sKzgttaQo5VmjWPtwyOJXODR2lHKQR2hFCkIKlHMPLV3awCGV8iTyiTZMJirdtvf
s26oA/9STYro+yB9yrHufdfjM1u8SbSIhK6jUoq2ajLPHaLF2nRZZyv1gnkzRFd+
/Vxcx6cwp8Qd6L4z+0sU3pMS4X8rt2vqilK2msg1VrHnjGgFIfmfIvY5EmrhNzEx
6X82fbR9f8lwLy5N/gPm326e0xSw1rWdR15VukJPbmK6nf/pL7RcUHVibGljIE9u
bHkgVGVzdCBLZXkgKGRvIG5vdCBlbmNyeXB0IGltcG9ydGFudCBkYXRhIHdpdGgg
dGhpcyBrZXkpIDxwdWJsaWMtb25seUBleGFtcGxlLmNvbT6IYAQTEQIAIAUCSNL4
4gIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEKuoHvVOjA3r8DYAn1/DrF5j
w31P3L6MlWdelLuR4POnAJ9It7IynfJalYIHoAWtY2xkkTsT+rkCDQRI0vjoEAgA
p65R578Es8qtASDAgIbYfJlJTwMovEnA4KJ69mpVt3mzcFWMtJCvuilvwSQQ+VfK
xjemtbe/IbMe9ssj4nTSLw/mweUB89tRj8ZzaS+/9312AS8ra/xIDr6kTSfKcRKj
XgMzkJ+A13rYwG5LFWnyumg36xglmzXKhecEkRVPfWn3ISoq3zirZlQOWcKYdyA2
Z685SKJC/N+3nUqKOJ7qrA7eT608LFksytBHeOfNf5m7CC4wAE3RAz+ZkJvWRbE2
G5pUalZktq8uKMT5WQgvuFP3hnvku5yilpo2ELTnYkO3ltc3NHCc9v+jhikayPr7
RvUdVPbaITT80yYKBPygCwADBggApzR1vW/fvzmrO5pWzAvd4umVh/Yp34n3vWyX
Mu+JIHA7s08rkTzlMXzamICQmkjwAuCwJt0t7BA28Lnygoh2joxo8tE/OowFk+Iz
beA2Vrz71d/T5SMDtC2mePE0m3bmCOLBscu5aJIfgi1X/fzr44f4i+6hqVDCuOOm
nVtbL4xBBnS6KXdcWP7QbVhxG3SpH9Agd/QXvSQm0Obz9iKZ11FEXzgnVZGXaCM0
GBsFE9JuNY5+hi6A72rccjhC0V1Cy43veeIhOE+v3pK0a/BGUlgDSdgVopE9zUSQ
wzuo87UbY3EoDWBqDRSRCRMfmv8S2b9VJIRPdCOHZGCIR49/0YhJBBgRAgAJBQJI
0vjoAhsMAAoJEKuoHvVOjA3rNsAAoJU2elOyfOy9SCds+dBGjwH1H8+ZAKDCLYlj
KsfZIC+ySVrE2gkwQS9gkg==
=hSJS
-----END PGP PUBLIC KEY BLOCK-----

TEXT;
        // }}}

        $keyData = $this->gpg->exportPublicKey($keyId);

        // Check for containment rather than equality since the OpenPGP header
        // varies from system to system.
        $this->assertContains($expectedKeyData, $keyData);
    }

    // }}}
    // {{{ testExportPublicKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group export
     */
    public function testExportPublicKeyNotFoundException()
    {
        $keyId = 'non-existent-key@example.com';
        $keyData = $this->gpg->exportPublicKey($keyId);
    }

    // }}}
}

?>
