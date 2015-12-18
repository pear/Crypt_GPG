<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key retrieval tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit GetKeysTestCase
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
 * Tests key retrieval of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class GetKeysTestCase extends Crypt_GPG_TestCase
{
    // {{{ testGetKeys()

    /**
     * @group get-keys
     */
    public function testGetKeys()
    {
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
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(true);
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
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);
        // }}}
        // {{{ second-keypair@example.com
        $key = new Crypt_GPG_Key();
        $expectedKeys[] = $key;

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $key->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('03CC890AFA1DAD4B');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setFingerprint('880922DBEA733E906693E4A903CC890AFA1DAD4B');
        $subKey->setLength(1024);
        $subKey->setCreationDate(1221785821);
        $subKey->setExpirationDate(0);
        $subKey->setUsage(Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_CERTIFY);
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('B2F54E4757E22450');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setFingerprint('C641EE162B46B810E8089153B2F54E4757E22450');
        $subKey->setLength(2048);
        $subKey->setCreationDate(1221785825);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);
        // }}}
        // {{{ public-only@example.com
        $key = new Crypt_GPG_Key();
        $expectedKeys[] = $key;

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Public Only Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('public-only@example.com');
        $key->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('ABA81EF54E8C0DEB');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setFingerprint('F83118CB6F5892DC1C3E936DABA81EF54E8C0DEB');
        $subKey->setLength(1024);
        $subKey->setCreationDate(1221785826);
        $subKey->setExpirationDate(0);
        $subKey->setUsage(Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_CERTIFY);
        $subKey->setHasPrivate(false);
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('BA4984433CDF4169');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setFingerprint('B68C9DB020181C798047A6E7BA4984433CDF4169');
        $subKey->setLength(2048);
        $subKey->setCreationDate(1221785832);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(false);
        $key->addSubKey($subKey);
        // }}}
        // {{{ no-passphrase@example.com
        $key = new Crypt_GPG_Key();
        $expectedKeys[] = $key;

        $userId = new Crypt_GPG_UserId();
        $userId->setName('No Passphrase Public and Private Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('no-passphrase@example.com');
        $key->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('94563FB398ADA6B2');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setFingerprint('1EC9C5DBF239DD0A3A4FCD0D94563FB398ADA6B2');
        $subKey->setLength(1024);
        $subKey->setCreationDate(1221785833);
        $subKey->setExpirationDate(0);
        $subKey->setUsage(Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_CERTIFY);
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('24BF380700C14B4F');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setFingerprint('86DD46AC210531EE5A37567824BF380700C14B4F');
        $subKey->setLength(2048);
        $subKey->setCreationDate(1221785845);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);
        // }}}
        // {{{ multiple-subkeys@example.com
        $key = new Crypt_GPG_Key();
        $expectedKeys[] = $key;

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Multiple Subkeys');
        $userId->setEmail('multiple-subkeys@example.com');
        $key->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('B07A621DC9295765');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setFingerprint('F9DF21B5D2DD02D3DF760270B07A621DC9295765');
        $subKey->setLength(1024);
        $subKey->setCreationDate(1232605399);
        $subKey->setExpirationDate(0);
        $subKey->setUsage(Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_CERTIFY | Crypt_GPG_SubKey::USAGE_AUTHENTICATION);
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('6F941ACC362453DA');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setFingerprint('A728EE198BA2FB5C7B1C8B896F941ACC362453DA');
        $subKey->setLength(2048);
        $subKey->setCreationDate(1232605407);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setId('2921E0D3FF5B0F4A');
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_RSA);
        $subKey->setFingerprint('E1363DCE4863B824813AB2702921E0D3FF5B0F4A');
        $subKey->setLength(2048);
        $subKey->setCreationDate(1232605437);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);
        // }}}

        $keys = $this->gpg->getKeys();
        $this->assertEquals($expectedKeys, $keys);
    }

    // }}}
    // {{{ testGetKeysWithKeyId()

    /**
     * @group get-keys
     */
    public function testGetKeysWithKeyId()
    {
        $keyId = 'first-keypair@example.com';
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
        $subKey->setHasPrivate(true);
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
        $subKey->setHasPrivate(true);
        $key->addSubKey($subKey);
        // }}}

        $keys = $this->gpg->getKeys($keyId);
        $this->assertEquals($expectedKeys, $keys);
    }

    // }}}
    // {{{ testGetKeysNone()

    /**
     * @group get-keys
     */
    public function testGetKeysNone()
    {
        $keyId = 'non-existent-key@example.com';
        $expectedKeys = array();
        $keys = $this->gpg->getKeys($keyId);
        $this->assertEquals($expectedKeys, $keys);
    }

    // }}}
}

?>
