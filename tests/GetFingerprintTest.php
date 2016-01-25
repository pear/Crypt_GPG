<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Fingerprint retrieval tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit GetFingerprintTestCase
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
 * Tests fingerprint retrieval of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class GetFingerprintTestCase extends Crypt_GPG_TestCase
{
    // {{{ testGetFingerprint()

    /**
     * @group get-fingerprint
     */
    public function testGetFingerprint()
    {
        $keyId = 'public-only@example.com';
        $expectedFingerprint = 'F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB';
        $fingerprint = $this->gpg->getFingerprint($keyId);
        $this->assertEquals($expectedFingerprint, $fingerprint);
    }

    // }}}
    // {{{ testGetFingerprintNull()

    /**
     * @group get-fingerprint
     */
    public function testGetFingerprintNull()
    {
        $keyId = 'non-existent-key@example.com';
        $fingerprint = $this->gpg->getFingerprint($keyId);
        $this->assertNull($fingerprint);
    }

    // }}}
    // {{{ testGetFingerprintX509()

    /**
     * @group get-fingerprint
     */
    public function testGetFingerprintX509()
    {
        $keyId = 'public-only@example.com';
        $expectedFingerprint =
            'F8:31:18:CB:6F:58:92:DC:1C:3E:93:6D:AB:A8:1E:F5:4E:8C:0D:EB';

        $fingerprint = $this->gpg->getFingerprint($keyId,
            Crypt_GPG::FORMAT_X509);

        $this->assertEquals($expectedFingerprint, $fingerprint);
    }

    // }}}
    // {{{ testGetFingerprintCanonical()

    /**
     * @group get-fingerprint
     */
    public function testGetFingerprintCanonical()
    {
        $keyId = 'public-only@example.com';
        $expectedFingerprint =
            'F831 18CB 6F58 92DC 1C3E  936D ABA8 1EF5 4E8C 0DEB';

        $fingerprint = $this->gpg->getFingerprint($keyId,
            Crypt_GPG::FORMAT_CANONICAL);

        $this->assertEquals($expectedFingerprint, $fingerprint);
    }

    // }}}
}

?>
