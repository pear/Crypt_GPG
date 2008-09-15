<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Private key deletion tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
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
 * Tests private key deletion abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class DeletePrivateKeyTestCase extends TestCase
{
    // {{{ testDeletePrivateKey()

    /**
     * @group delete-private
     */
    public function testDeletePrivateKey()
    {
        $keyId = 'public-and-private@example.com';
        $this->gpg->deletePrivateKey($keyId);

        $expectedKeys = array();

        // {{{ public-and-private@example.com
        $key = new Crypt_GPG_Key();
        $expectedKeys[] = $key;

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Public and Private Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('public-and-private@example.com');
        $key->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('300579D099645239');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setFingerprint('5A58436F752BC80B3E992C1D300579D099645239');
        $subKey->setLength(1024);
        $subKey->setCreationDate(1200670392);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(true);
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(false);
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('EBEB1F9895953487');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setFingerprint('DCC9E7AAB9248CB0541FADDAEBEB1F9895953487');
        $subKey->setLength(2048);
        $subKey->setCreationDate(1200670397);
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
