<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key export tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
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
class ExportPublicKeyTestCase extends Crypt_GPG_TestCase
{
    // {{{ testExportPublicKey()

    /**
     * @group export
     */
    public function testExportPublicKey()
    {
        $keyId = 'public-only@example.com';

        // We can't expect the key data to be identical as the one
        // at the creation time, so we only check if it's valid format
        $expectedKeyData = "-----END PGP PUBLIC KEY BLOCK-----";

        $keyData = $this->gpg->exportPublicKey($keyId);

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
        $this->gpg->exportPublicKey($keyId);
    }

    // }}}
}

?>
