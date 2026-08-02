<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG\Exceptions;

/**
 * Tests encrypt and sign abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2009 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class EncryptAndSignTest extends TestCase
{
    /**
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_invalid_sign_key()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('non-existent-key@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

    /**
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_no_sign_key()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

    /**
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_invalid_encrypt_key()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('non-existent-key@example.com');
        $this->gpg->encryptAndSign($data);
    }

    /**
     * @group string
     */
    public function testEncryptAndSignKeyNotFoundException_no_encrypt_key()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->encryptAndSign($data);
    }

    /**
     * @group string
     */
    public function testEncryptAndSignBadPassphraseException_missing_sign_key()
    {
        $this->expectException(Exceptions\BadPassphraseException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

    /**
     * @group string
     */
    public function testEncryptAndSignBadPassphraseException_bad_sign_key()
    {
        $this->expectException(Exceptions\BadPassphraseException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'incorrect');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSign($data);
    }

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

    /**
     * @group file
     */
    public function testEncryptAndSignFileNoPassphrase()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $encryptedFilename,
            $decryptedFilename
        );

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    /**
     * @group file
     */
    public function testEncryptAndSignFile()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $encryptedFilename,
            $decryptedFilename
        );

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(1, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    /**
     * @group file
     */
    public function testEncryptAndSignFileDualOnePassphrase()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $encryptedFilename,
            $decryptedFilename
        );

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(2, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    /**
     * @group file
     */
    public function testEncryptAndSignFileDual()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.asc');

        $decryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileNoPassphrase.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $encryptedFilename,
            $decryptedFilename
        );

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        $this->assertEquals(2, count($results['signatures']));
        foreach ($results['signatures'] as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    /**
     * @group file
     */
    public function testEncryptAndSignFileFileException_input()
    {
        $this->expectException(Exceptions\FileException::class);

        // input file does not exist
        $inputFilename = $this->getDataFilename(
            'testEncryptAndSignFileFileFileException_input.plain'
        );

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($inputFilename);
    }

    /**
     * @group file
     */
    public function testEncryptAndSignFileFileException_output()
    {
        $this->expectException(Exceptions\FileException::class);

        // input file is plaintext
        // output file does not exist
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = './non-existent'
            . '/testEncryptAndSignFileFileException_output.plain';

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptAndSignFile($inputFilename, $outputFilename);
    }

    /**
     * @group file
     */
    public function testEncryptAndSignFileEmpty()
    {
        $originalFilename  = $this->getDataFilename('testFileEmpty.plain');
        $encryptedFilename
            = $this->getTempFilename('testEncryptAndSignFileEmpty.asc');

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
}
