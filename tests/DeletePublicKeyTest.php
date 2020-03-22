<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Public key deletion tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit DeletePublicKeyTestCase
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
 * Tests public key deletion abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class DeletePublicKeyTestCase extends Crypt_GPG_TestCase
{
    // {{{ testDeletePublicKey()

    /**
     * @group delete-public
     */
    public function testDeletePublicKey()
    {
        $keyId = 'public-only@example.com';
        $this->gpg->deletePublicKey($keyId);

        $expectedKeys = array();
        $keys = $this->gpg->getKeys($keyId);
        $this->assertEquals($expectedKeys, $keys);
    }

    // }}}
    // {{{ testDeletePublicKeyDeletePrivateKeyException()

    /**
     * @expectedException Crypt_GPG_DeletePrivateKeyException
     *
     * @group delete-public
     */
    public function testDeletePublicKeyDeletePrivateKeyException()
    {
        // GnuPG 2.1(.11) allows public key deletion in this case
        if (version_compare($this->gpg->getVersion(), '2.1.0', 'ge')) {
            $this->markTestSkipped('GnuPG >= 2.1 allows public key deletion if private key exists.');
        }

        $keyId = 'first-keypair@example.com';
        $this->gpg->deletePublicKey($keyId);
    }

    // }}}
    // {{{ testDeletePublicKey_privExists()

    /**
     * @group delete-public
     */
    public function testDeletePublicKey_privExists()
    {
        // GnuPG 2.1(.11) allows public key deletion in this case
        if (version_compare($this->gpg->getVersion(), '2.1.0', 'lt')) {
            $this->markTestSkipped('GnuPG >= 2.1 allows public key deletion if private key exists.');
        }

        $keyId = 'first-keypair@example.com';
        $this->gpg->deletePublicKey($keyId);

        $this->assertTrue(true);
    }

    // }}}
    // {{{ testDeletePublicKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group delete-public
     */
    public function testDeletePublicKeyNotFoundException()
    {
        $keyId = 'non-existent-key@example.com';
        $this->gpg->deletePublicKey($keyId);
    }

    // }}}
}

?>
