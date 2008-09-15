<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Fingerprint retrieval tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
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
 * Tests fingerprint retrieval of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class GetFingerprintTestCase extends TestCase
{
    // {{{ testGetFingerprint()

    /**
     * @group get-fingerprint
     */
    public function testGetFingerprint()
    {
        $keyId = 'public-only@example.com';
        $expectedFingerprint = 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4';
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
            'C3:BC:61:5A:D9:C7:66:E5:A8:5C:1F:27:16:D2:74:58:B1:BB:A1:C4';

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
            'C3BC 615A D9C7 66E5 A85C  1F27 16D2 7458 B1BB A1C4';

        $fingerprint = $this->gpg->getFingerprint($keyId,
            Crypt_GPG::FORMAT_CANONICAL);

        $this->assertEquals($expectedFingerprint, $fingerprint);
    }

    // }}}
}

?>
