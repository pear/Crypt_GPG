<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Private key deletion tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit DeletePrivateKeyTestCase
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
 * Tests private key deletion abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class DeletePrivateKeyTestCase extends Crypt_GPG_TestCase
{
    // {{{ testDeletePrivateKey()

    /**
     * @group delete-private
     */
    public function testDeletePrivateKey()
    {
        $keyId = 'first-keypair@example.com';
        $this->gpg->deletePrivateKey($keyId);

        $expectedKeys = array();

        // {{{ first-keypair@example.com
        $key = new Crypt_GPG_Key();
        $expectedKeys[] = $key;

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $key->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('C097D9EC94C06363');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setFingerprint('8D2299D9C5C211128B32BBB0C097D9EC94C06363');
        $subKey->setLength(1024);
        $subKey->setCreationDate(1221785805);
        $subKey->setExpirationDate(0);
        $subKey->setUsage(Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_CERTIFY);
        $subKey->setHasPrivate(false);
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('9F93F9116728EF12');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setFingerprint('C9C65B3BBF040E40D0EA27B79F93F9116728EF12');
        $subKey->setLength(2048);
        $subKey->setCreationDate(1221785821);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(false);
        $key->addSubKey($subKey);
        // }}}

        $keys = $this->gpg->getKeys($keyId);
        $this->assertEquals($expectedKeys, $keys);
    }

    // }}}
    // {{{ testDeletePrivateKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group delete-private
     */
    public function testDeletePrivateKeyNotFoundException()
    {
        $keyId = 'non-existent-key@example.com';
        $this->gpg->deletePrivateKey($keyId);
    }

    // }}}
    // {{{ testDeletePrivateKeyNotFoundException_public_only()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group delete-private
     */
    public function testDeletePrivateKeyNotFoundException_public_only()
    {
        $keyId = 'public-only@example.com';
        $this->gpg->deletePrivateKey($keyId);
    }

    // }}}
}

?>
