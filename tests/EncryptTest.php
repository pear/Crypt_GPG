<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG\Exceptions;

/**
 * Tests encryption abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class EncryptTest extends TestCase
{
    public function testHasEncryptKeys()
    {
        $this->assertFalse($this->gpg->hasEncryptKeys());
        $this->gpg->addEncryptKey('no-passphrase@example.com');
        $this->assertTrue($this->gpg->hasEncryptKeys());
    }

    /**
     * @group string
     */
    public function testEncrypt()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'first-keypair@example.com';
        $passphrase = 'test1';

        $this->gpg->addEncryptKey($keyId);
        $encryptedData = $this->gpg->encrypt($data);

        $this->gpg->addDecryptKey($keyId, $passphrase);
        $decryptedData = $this->gpg->decrypt($encryptedData);

        $this->assertEquals($data, $decryptedData);
    }

    /**
     * @group string
     */
    public function testEncryptDual()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->addEncryptKey('second-keypair@example.com');
        $encryptedData = $this->gpg->encrypt($data);

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($data, $decryptedData);
        $this->gpg->clearDecryptKeys();

        // decrypt with second key
        $this->gpg->addDecryptKey('second-keypair@example.com', 'test2');
        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->gpg->clearDecryptKeys();
        $this->assertEquals($data, $decryptedData);
    }

    /**
     * @group string
     */
    public function testEncryptNotFoundException_invalid()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addEncryptKey('non-existent-key@example.com');
        $this->gpg->encrypt($data);
    }

    /**
     * @group string
     */
    public function testEncryptNotFoundException_none()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->encrypt($data);
    }

    /**
     * @group string
     */
    public function testEncryptEmpty()
    {
        $data = '';

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $encryptedData = $this->gpg->encrypt($data);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $decryptedData = $this->gpg->decrypt($encryptedData);

        $this->assertEquals($data, $decryptedData);
    }

    /**
     * @group file
     */
    public function testEncryptFile()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename = $this->getTempFilename('testEncryptFile.asc');
        $decryptedFilename = $this->getTempFilename('testEncryptFile.plain');

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptFile($originalFilename, $encryptedFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptFile($encryptedFilename, $decryptedFilename);

        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    /**
     * @group file
     */
    public function testEncryptFileDual()
    {
        $expectedMd5Sum    = 'f96267d87551ee09bfcac16921e351c1';
        $originalFilename  = $this->getDataFilename('testFileMedium.plain');
        $encryptedFilename = $this->getTempFilename('testEncryptFile.asc');
        $decryptedFilename = $this->getTempFilename('testEncryptFile.plain');

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->addEncryptKey('second-keypair@example.com');
        $this->gpg->encryptFile($originalFilename, $encryptedFilename);

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptFile($encryptedFilename, $decryptedFilename);
        $this->gpg->clearDecryptKeys();
        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        // decrypt with second key
        $this->gpg->addDecryptKey('second-keypair@example.com', 'test2');
        $this->gpg->decryptFile($encryptedFilename, $decryptedFilename);
        $this->gpg->clearDecryptKeys();
        $md5Sum = $this->getMd5Sum($decryptedFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    /**
     * @group file
     */
    public function testEncryptFileToString()
    {
        $expectedData     = 'Hello, Alice! Goodbye, Bob!';
        $originalFilename = $this->getDataFilename('testFileSmall.plain');

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $encryptedData = $this->gpg->encryptFile($originalFilename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $decryptedData = $this->gpg->decrypt($encryptedData);

        $this->assertEquals($expectedData, $decryptedData);
    }

    /**
     * @group file
     */
    public function testEncryptFileFileException_input()
    {
        $this->expectException(Exceptions\FileException::class);

        // input file does not exist
        $filename
            = $this->getDataFilename('testEncryptFileFileException_input.plain');

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptFile($filename);
    }

    /**
     * @group file
     */
    public function testEncryptFileFileException_output()
    {
        $this->expectException(Exceptions\FileException::class);

        // output file does not exist
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = './non-existent'
            . '/testEncryptFileFileException_output.asc';

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $this->gpg->encryptFile($inputFilename, $outputFilename);
    }

    /**
     * @group file
     */
    public function testEncryptFileEmpty()
    {
        $filename = $this->getDataFilename('testFileEmpty.plain');

        $this->gpg->addEncryptKey('first-keypair@example.com');
        $encryptedData = $this->gpg->encryptFile($filename);

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $decryptedData = $this->gpg->decrypt($encryptedData);

        $this->assertEquals('', $decryptedData);
    }
}
