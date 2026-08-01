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
 * @link      http://pear.php.net/package/Crypt_GPG
 */

namespace Crypt\GPG\Tests;

use Crypt\GPG;
use Crypt\GPG\Exceptions;
use Crypt\GPG\Key;
use Crypt\GPG\SubKey;
use Crypt\GPG\UserId;

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
class DeletePrivateKeyTest extends TestCase
{
    /**
     * @group delete-private
     */
    public function testDeletePrivateKey()
    {
        $keyId = 'first-keypair@example.com';
        $this->gpg->deletePrivateKey($keyId);

        $expectedKeys = [];

        // {{{ first-keypair@example.com
        $key = new Key();
        $expectedKeys[] = $key;

        $userId = new UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $key->addUserId($userId);

        $subKey = new SubKey();
        $subKey->setId('C097D9EC94C06363');
        $subKey->setAlgorithm(SubKey::ALGORITHM_DSA);
        $subKey->setFingerprint('8D2299D9C5C211128B32BBB0C097D9EC94C06363');
        $subKey->setLength(1024);
        $subKey->setCreationDate(1221785805);
        $subKey->setExpirationDate(0);
        $subKey->setUsage(SubKey::USAGE_SIGN | SubKey::USAGE_CERTIFY);
        $subKey->setHasPrivate(false);
        $key->addSubKey($subKey);

        $subKey = new SubKey();
        $subKey->setId('9F93F9116728EF12');
        $subKey->setAlgorithm(SubKey::ALGORITHM_ELGAMAL_ENC);
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

    /**
     * @group delete-private
     */
    public function testDeletePrivateKeyNotFoundException()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $keyId = 'non-existent-key@example.com';
        $this->gpg->deletePrivateKey($keyId);
    }

    /**
     * @group delete-private
     */
    public function testDeletePrivateKeyNotFoundException_public_only()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $keyId = 'public-only@example.com';
        $this->gpg->deletePrivateKey($keyId);
    }
}
