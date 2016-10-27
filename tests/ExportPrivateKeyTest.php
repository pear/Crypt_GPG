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

        // We can't expect the key data to be identical as the one
        // at the creation time, so we only check if it's valid format
        $expectedKeyData = "-----END PGP PRIVATE KEY BLOCK-----";

        // Note: This operation expects passphrase in GnuPG 2.1 < 2.1.15
        //       because of https://bugs.gnupg.org/gnupg/issue2070.

        $keyData = $this->gpg->exportPrivateKey($keyId);

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

        // This operation requires passphrase in GnuPG 2.1
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

        // This operation requires passphrase in GnuPG 2.1
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
