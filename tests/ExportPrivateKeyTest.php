<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Private key export tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit ExportPrivateKeyTestCase
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
 * Tests key export abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class ExportPrivateKeyTestCase extends Crypt_GPG_TestCase
{
    // {{{ testExportPrivateKey()

    /**
     * @group export
     */
    public function testExportPrivateKey()
    {
        $keyId = 'no-passphrase@example.com';

        // {{{ expected key data
        // Key block identifier and version identifier intentionally omitted
        // because they contain system-specific information, and causes tests
        // to fail on other systems.
        $expectedKeyData = <<<TEXT
lQG7BEjS+OkRBACyn20BV58+x0c2Fq49TLtrWQBCT9VxnNdeCUJ4sEgomTEUhYXu
LAJ7UmORwjhT16l2X7EJKXZEfEbfZI8j/iYnpIBp/iYtsZ8y6bN70wdeNpRtZkB3
Cu1mU5C6d/thw0TmedW93bQ06wMtzBEPEQuOM+YjiKQZjjgqFmln5T3ctwCg6b/H
8//3jEa2N5J8U4yTOxZjxUMD/ROX/utLDNKX+dTLy69uQrlr94tabwszpBgdTYMw
zgefgUYDdR7esWM5rZ5MMJX9lPzeePMPf0/7RllhYA4XgJ7EvzVTGNAuL45LVJrG
9B5dhwrChoKFNUtCfINS61urPdhUQA8YzmUxI+iDgBkD4FujLoh8ww+pxupJRsYZ
b39iA/0ZJKZOeIN3JyUrIlqSqENG549H0+Y4TC5t8YixafB8fPBjlMz0+xGMR3Xx
b8WHD+XFdulr/sVZ4WZ00YtOGhS/3ZF7qGrxCCBrCAjDRdPzqaF15nMaqgIogOIO
L5j9wI6wRpMsJBxEbttWR/9K4BXhBriwg9qv4vamwzFM0t2vLQAAnRezOzJCxMwH
xJHP1w6hpE8EQXV2CXq0c05vIFBhc3NwaHJhc2UgUHVibGljIGFuZCBQcml2YXRl
IFRlc3QgS2V5IChkbyBub3QgZW5jcnlwdCBpbXBvcnRhbnQgZGF0YSB3aXRoIHRo
aXMga2V5KSA8bm8tcGFzc3BocmFzZUBleGFtcGxlLmNvbT6IYAQTEQIAIAUCSNL4
6QIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEJRWP7OYraayJmcAoMNHBJD2
jyN3z33NoeWeo+E8rh0mAJ9GYB60jPdeAy8QI8HecG15bd7kAZ0CPQRI0vj1EAgA
hewinC9zCUsdDq6ajNdMztkTKyuhZuNB/7a0xBWuS2ugUobAEU549c7BuUYw8B9q
pW1krb5ZDOa/szWN6FkWoyJwKG6POp38bASCZ0JL3QLcrSEENjdmqsjWggQEwfFa
Teb15PLEPJQW1m5WgD31Cf5HCBRQmPMgsI2r9XDiLFJm8BdJ6JTtV9UHwCbM/kA7
U3RrL30uVfreJYhPepQvjkfU66ZzHADjmpu2d8iMee1I7d581NecYG9U87LZf2Xr
9r2m4YmiGO5w/oKVyMXuJfNAgMSMu9EIF+whBFdQjlZ2nEfwf0K1oU/Eod1lKTRA
FYcpDlwhO5M18pIcc4gI+wADBQf/d5ISDTDuirgkyFOi1sJxk/avD10NNvmaXYxc
2gTYF7Natkq0T0x2behWwNbO3DhZOFrZqlj+mkg9LRx/Q0XMviac1X0ils20MdS2
PSa8wkg8BC+2RVbV6DrNAyF+E2+9penGulTgKsPIybn0azBgVkfoRBjpTu8D8xFH
+ASaZUt+850oynFlDmAXWfqU5pcTMVEny+KrY62S6TDH2zLEfIJKK97oRuU9F86A
UbAIn575fUHJnzgEoelxKJTWWlDCH9IPq37ZrStNeOBqURgzttvMaL7/zhcVPIEw
9WFgG8TCEpYNOg+x0gqETHM2rIRBdGfjgaSY7T9fXoxiikv37AABVAg+anwLssMt
ypICzst26P2lLSCGT1f7icmHvSqBgVdOQizx/9QYGMoUigAUyohJBBgRAgAJBQJI
0vj1AhsMAAoJEJRWP7OYraaywmQAoK31UjQ8v0JxjEBYQISdvYuLNpA8AKC7QxpJ
WOad2BFLoSh6WM3H7KvMUg==
=ZTyB
-----END PGP PRIVATE KEY BLOCK-----
TEXT;
        // }}}

        // @TODO: This operation requires passphrase in GnuPG 2.1(.11)
        //        because of https://bugs.gnupg.org/gnupg/issue2070.

        $keyData = $this->gpg->exportPrivateKey($keyId);

        // Check for containment rather than equality since the OpenPGP header
        // varies from system to system.
        $this->assertContains($expectedKeyData, $keyData);
    }

    // }}}
    // {{{ testExportPrivateKey_with_good_pass()

    /**
     * @group export
     */
    public function testExportPrivateKey_with_good_pass()
    {
        if (version_compare($this->gpg->getVersion(), '2.1.0', 'lt')) {
            $this->markTestSkipped('GnuPG >= 2.1 requires passphrase to export private key.');
        }

        $keyId = 'first-keypair@example.com';

        // This operation requires passphrase in GnuPG 2.1(.11)
        $this->gpg->addPassphrase('94C06363', 'test1');

        $keyData = $this->gpg->exportPrivateKey($keyId);

        // Here we're really testing only the passphrase handling in GnuPG 2.1
        $this->assertContains('PGP PRIVATE KEY', $keyData);
    }

    // }}}
    // {{{ testExportPrivateKey_with_bad_pass()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group export
     */
    public function testExportPrivateKey_with_bad_pass()
    {
        if (version_compare($this->gpg->getVersion(), '2.1.0', 'lt')) {
            $this->markTestSkipped('GnuPG >= 2.1 requires passphrase to export private key.');
        }

        $keyId = 'first-keypair@example.com';

        // This operation requires passphrase in GnuPG 2.1(.11)
        $this->gpg->addPassphrase('94C06363', 'bad');

        $keyData = $this->gpg->exportPrivateKey($keyId);
    }

    // }}}
    // {{{ testExportPrivateKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group export
     */
    public function testExportPrivateKeyNotFoundException()
    {
        $keyId = 'non-existent-key@example.com';
        $this->gpg->exportPrivateKey($keyId);
    }

    // }}}
}

?>
