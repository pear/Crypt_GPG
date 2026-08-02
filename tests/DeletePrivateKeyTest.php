<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

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
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
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
