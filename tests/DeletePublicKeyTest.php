<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG\Exceptions;

/**
 * Tests public key deletion abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class DeletePublicKeyTest extends TestCase
{
    /**
     * @group delete-public
     */
    public function testDeletePublicKey()
    {
        $keyId = 'public-only@example.com';
        $this->gpg->deletePublicKey($keyId);

        $expectedKeys = [];
        $keys = $this->gpg->getKeys($keyId);
        $this->assertEquals($expectedKeys, $keys);
    }

    /**
     * @group delete-public
     * @doesNotPerformAssertions
     */
    public function testDeletePublicKey_privExists()
    {
        $keyId = 'first-keypair@example.com';
        $this->gpg->deletePublicKey($keyId);
    }

    /**
     * @group delete-public
     */
    public function testDeletePublicKeyNotFoundException()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $keyId = 'non-existent-key@example.com';
        $this->gpg->deletePublicKey($keyId);
    }
}
