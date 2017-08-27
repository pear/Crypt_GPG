<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Encrypt and sign tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit EncryptSignTestCase
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
 * @copyright 2005-2009 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * Tests encrypt and sign abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2009 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class EncryptAndSignTestCase extends Crypt_GPG_TestCase
{
    // string
    // {{{ testEncryptAndSignKeyNotFoundException_invalid_sign_key()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_invalid_sign_key()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('non-existent-key@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

    // }}}
    // {{{ testEncryptAndSignKeyNotFoundException_no_sign_key()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_no_sign_key()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

    // }}}
    // {{{ testEncryptAndSignKeyNotFoundException_invalid_encrypt_key()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_invalid_encrypt_key()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('non-existent-key@example.com');
        $this->gpg->encryptAndSign($data);
    }

    // }}}
    // {{{ testEncryptAndSignKeyNotFoundException_no_encrypt_key()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_no_encrypt_key()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->encryptAndSign($data);
    }

    // }}}
    // {{{ testEncryptAndSignBadPassphraseException_missing_sign_key()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testEncryptAndSignBadPassphraseException_missing_sign_key()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

    // }}}
    // {{{ testEncryptAndSignBadPassphraseException_bad_sign_key()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testEncryptAndSignBadPassphraseException_bad_sign_key()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'incorrect');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

    // }}}
    // {{{ testEncryptAndSignNoPassphrase()

    /**
     * @group string
     */
    public function testEncryptAndSignNoPassphrase()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        $signKey           = 'no-passphrase@example.com';
        $encryptKey        = 'first-keypair@example.com';
        $decryptPassphrase = 'test1';

        $this->gpg->addSignKey($signKey);
        $this->gpg->addEncryptKey($encryptKey);
        $encryptedSignedData = $this->gpg->encryptAndSign($data);

        $this->gpg->addDecryptKey($encryptKey, $decryptPassphrase);
        $results = $this->gpg->decryptAndVerify($encryptedSignedData);

        $this->assertEquals($data, $results['data']);
        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSign()

    /**
     * @group string
     */
    public function testEncryptAndSign()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        $signKey           = 'first-keypair@example.com';
        $signPassphrase    = 'test1';
        $encryptKey        = 'first-keypair@example.com';
        $decryptPassphrase = 'test1';

        $this->gpg->addSignKey($signKey, $signPassphrase);
        $this->gpg->addEncryptKey($encryptKey);
        $encryptedSignedData = $this->gpg->encryptAndSign($data);

        $this->gpg->addDecryptKey($encryptKey, $decryptPassphrase);
        $results = $this->gpg->decryptAndVerify($encryptedSignedData);

        $this->assertEquals($data, $results['data']);
        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignDualOnePassphrase()

    /**
     * @group string
     */
    public function testEncryptAndSignDualOnePassphrase()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        $signKey1          = 'first-keypair@example.com';
        $signPassphrase1   = 'test1';
        $signKey2          = 'no-passphrase@example.com';
        $encryptKey        = 'first-keypair@example.com';
        $decryptPassphrase = 'test1';

        $this->gpg->addSignKey($signKey1, $signPassphrase1);
        $this->gpg->addSignKey($signKey2);
        $this->gpg->addEncryptKey($encryptKey);
        $encryptedSignedData = $this->gpg->encryptAndSign($data);

        $this->gpg->addDecryptKey($encryptKey, $decryptPassphrase);
        $results = $this->gpg->decryptAndVerify($encryptedSignedData);

        $this->assertEquals($data, $results['data']);
        $this->assertEquals(2, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignDual()

    /**
     * @group string
     */
    public function testEncryptAndSignDual()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        $signKey1          = 'first-keypair@example.com';
        $signPassphrase1   = 'test1';
        $signKey2          = 'second-keypair@example.com';
        $signPassphrase2   = 'test2';
        $encryptKey        = 'first-keypair@example.com';
        $decryptPassphrase = 'test1';

        $this->gpg->addSignKey($signKey1, $signPassphrase1);
        $this->gpg->addSignKey($signKey2, $signPassphrase2);
        $this->gpg->addEncryptKey($encryptKey);
        $encryptedSignedData = $this->gpg->encryptAndSign($data);

        $this->gpg->addDecryptKey($encryptKey, $decryptPassphrase);
        $results = $this->gpg->decryptAndVerify($encryptedSignedData);

        $this->assertEquals($data, $results['data']);
        $this->assertEquals(2, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignEmpty()

    /**
     * @group string
     */
    public function testEncryptAndSignEmpty()
    {
        $data = '';

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $encryptedSignedData = $this->gpg->encryptAndSign($data);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerify($encryptedSignedData);

        $this->assertEquals('', $results['data']);
        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignFileNoPassphrase()

    /**
     * @group file
     */
    public function testEncryptAndSignFileNoPassphrase()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile($encryptedFilename,
            $decryptedFilename);

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignFile()

    /**
     * @group file
     */
    public function testEncryptAndSignFile()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile($encryptedFilename,
            $decryptedFilename);

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignFileDualOnePassphrase()

    /**
     * @group file
     */
    public function testEncryptAndSignFileDualOnePassphrase()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile($encryptedFilename,
            $decryptedFilename);

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(2, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignFileDual()

    /**
     * @group file
     */
    public function testEncryptAndSignFileDual()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile($encryptedFilename,
            $decryptedFilename);

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(2, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testEncryptAndSignFileFileException_input()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testEncryptAndSignFileFileException_input()
    {
        // input file does not exist
        $inputFilename = $this->getDataFilename(
            'testEncryptAndSignFileFileFileException_input.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($inputFilename);
    }

    // }}}
    // {{{ testEncryptAndSignFileFileException_output()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testEncryptAndSignFileFileException_output()
    {
        // input file is plaintext
        // output file does not exist
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = './non-existent' .
            '/testEncryptAndSignFileFileException_output.plain';

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($inputFilename, $outputFilename);
    }

    // }}}
    // {{{ testEncryptAndSignFileEmpty()

    /**
     * @group file
     */
    public function testEncryptAndSignFileEmpty()
    {
        $originalFilename  = $this->getDataFilename('testFileEmpty.plain');
        $encryptedFilename =
            $this->getTempFilename('testEncryptAndSignFileEmpty.asc');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile($encryptedFilename);

        $this->assertEquals('', $results['data']);

        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
}

?>
