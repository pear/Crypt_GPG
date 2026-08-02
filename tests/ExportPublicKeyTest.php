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
class ExportPublicKeyTest extends TestCase
{
    /**
     * @group export
     */
    public function testExportPublicKey()
    {
        $keyId = 'public-only@example.com';

        // We can't expect the key data to be identical as the one
        // at the creation time, so we only check if it's valid format
        $expectedKeyData = "-----END PGP PUBLIC KEY BLOCK-----\n";

        $keyData = $this->gpg->exportPublicKey($keyId);

        $this->assertStringEndsWith($expectedKeyData, $keyData);
    }

    /**
     * @group export
     */
    public function testExportPublicKeyNotFoundException()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $keyId = 'non-existent-key@example.com';
        $this->gpg->exportPublicKey($keyId);
    }
}
