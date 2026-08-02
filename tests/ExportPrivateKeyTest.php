<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG\Exceptions;

/**
 * Tests key export abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class ExportPrivateKeyTest extends TestCase
{
    /**
     * @group export
     */
    public function testExportPrivateKey()
    {
        $keyId = 'no-passphrase@example.com';

        // We can't expect the key data to be identical as the one
        // at the creation time, so we only check if it's valid format
        $expectedKeyData = "-----END PGP PRIVATE KEY BLOCK-----\n";

        $keyData = $this->gpg->exportPrivateKey($keyId);

        $this->assertStringEndsWith($expectedKeyData, $keyData);
    }

    /**
     * @group export
     */
    public function testExportPrivateKey_with_good_pass()
    {
        $keyId = 'first-keypair@example.com';

        $this->gpg->addPassphrase('94C06363', 'test1');

        $keyData = $this->gpg->exportPrivateKey($keyId);

        $this->assertStringStartsWith('-----BEGIN PGP PRIVATE KEY BLOCK-----', $keyData);
    }

    /**
     * @group export
     */
    public function testExportPrivateKey_with_bad_pass()
    {
        $this->expectException(Exceptions\BadPassphraseException::class);

        $keyId = 'first-keypair@example.com';

        $this->gpg->addPassphrase('94C06363', 'bad');

        $keyData = $this->gpg->exportPrivateKey($keyId);
    }

    /**
     * @group export
     */
    public function testExportPrivateKeyNotFoundException()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $keyId = 'non-existent-key@example.com';
        $this->gpg->exportPrivateKey($keyId);
    }
}
