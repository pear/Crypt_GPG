<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Signing tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit SignTestCase
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
 * Tests signing abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class SignTestCase extends Crypt_GPG_TestCase
{
    public function testHasSignKeys()
    {
        $this->assertFalse($this->gpg->hasSignKeys());
        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->assertTrue($this->gpg->hasSignKeys());
    }

    // {{{ testSignKeyNotFoundException_invalid()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testSignKeyNotFoundException_invalid()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('non-existent-key@example.com');
        $this->gpg->sign($data);
    }

    // }}}
    // {{{ testSignKeyNotFoundException_none()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testSignKeyNotFoundException_none()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->sign($data);
    }

    // }}}
    // {{{ testSignBadPassphraseException_missing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testSignBadPassphraseException_missing()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com');
        $this->gpg->sign($data);
    }

    // }}}
    // {{{ testSignBadPassphraseException_bad()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testSignBadPassphraseException_bad()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'incorrect');
        $this->gpg->sign($data);
    }

    // }}}
    // {{{ testSignNoPassphrase()

    /**
     * @group string
     */
    public function testSignNoPassphrase()
    {
        $this->gpg->setEngineOptions(array('sign' => '--emit-version'));

        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('no-passphrase@example.com');
        $signedData = $this->gpg->sign($data);

        // Check if --emit-version option works
        $this->assertTrue(strpos($signedData, 'Version:') !== false);
        $this->gpg->setEngineOptions(array());

        $signatures = $this->gpg->verify($signedData);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignNormal()

    /**
     * @group string
     */
    public function testSignNormal()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $signedData = $this->gpg->sign($data);

        $signatures = $this->gpg->verify($signedData);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignClear()

    /**
     * @group string
     */
    public function testSignClear()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $signedData = $this->gpg->sign($data, Crypt_GPG::SIGN_MODE_CLEAR);

        $signatures = $this->gpg->verify($signedData);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignDetached()

    /**
     * @group string
     */
    public function testSignDetached()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $signatureData = $this->gpg->sign($data,
            Crypt_GPG::SIGN_MODE_DETACHED);

        $signatures = $this->gpg->verify($data, $signatureData);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignDualOnePassphrase()

    /**
     * @group string
     */
    public function testSignDualOnePassphrase()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $signedData = $this->gpg->sign($data);

        $signatures = $this->gpg->verify($signedData);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignDualNormal()

    /**
     * @group string
     */
    public function testSignDualNormal()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $signedData = $this->gpg->sign($data);

        $signatures = $this->gpg->verify($signedData);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignDualClear()

    /**
     * @group string
     */
    public function testSignDualClear()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $signedData = $this->gpg->sign($data, Crypt_GPG::SIGN_MODE_CLEAR);

        $signatures = $this->gpg->verify($signedData);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignDualDetached()

    /**
     * @group string
     */
    public function testSignDualDetached()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $signatureData = $this->gpg->sign($data,
            Crypt_GPG::SIGN_MODE_DETACHED);

        $signatures = $this->gpg->verify($data, $signatureData);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignEmpty()

    /**
     * @group string
     */
    public function testSignEmpty()
    {
        $data = '';

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');

        $signedData = $this->gpg->sign($data);
        $signatures = $this->gpg->verify($signedData);

        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignDetachedTextmode()

    /**
     * @group string
     */
    public function testSignDetachedTextmode()
    {
        // data with Unix line endings
        $data = "It was the best of times,\n"
            . "it was the worst of times,\n"
            . "it was the age of wisdom,\n"
            . "it was the age of foolishness,\n"
            . "it was the epoch of belief,\n"
            . "it was the epoch of incredulity,\n"
            . "it was the season of Light,\n"
            . "it was the season of Darkness,\n"
            . "it was the spring of hope,\n"
            . "it was the winter of despair,";

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $signatureData = $this->gpg->sign(
            $data,
            Crypt_GPG::SIGN_MODE_DETACHED,
            true,
            true
        );

        // convert data to Windows line endings
        $data = str_replace("\n", "\r\n", $data);

        // verify data
        $signatures = $this->gpg->verify($data, $signatureData);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue(
                $signature->isValid(),
                'Failed asserting textmode signature is valid.'
            );
        }
    }

    // }}}
    // {{{ testSignFileNoPassphrase()

    /**
     * @group file
     */
    public function testSignFileNoPassphrase()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename =
            $this->getTempFilename('testSignFileNoPassphrase.asc');

        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->gpg->signFile($inputFilename, $outputFilename);

        $signatures = $this->gpg->verifyFile($outputFilename);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileNormal()

    /**
     * @group file
     */
    public function testSignFileNormal()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = $this->getTempFilename('testSignFileNormal.asc');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->signFile($inputFilename, $outputFilename);

        $signatures = $this->gpg->verifyFile($outputFilename);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileClear()

    /**
     * @group file
     */
    public function testSignFileClear()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = $this->getTempFilename('testSignFileClear.asc');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->signFile($inputFilename, $outputFilename,
            Crypt_GPG::SIGN_MODE_CLEAR);

        $signatures = $this->gpg->verifyFile($outputFilename);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileDetached()

    /**
     * @group file
     */
    public function testSignFileDetached()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = $this->getTempFilename('testSignFileDetached.asc');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->signFile($inputFilename, $outputFilename,
            Crypt_GPG::SIGN_MODE_DETACHED);

        $signatureData = file_get_contents($outputFilename);

        $signatures = $this->gpg->verifyFile($inputFilename, $signatureData);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileDetachedToString()

    /**
     * @group file
     */
    public function testSignFileDetachedToString()
    {
        $filename = $this->getDataFilename('testFileMedium.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $signatureData = $this->gpg->signFile($filename, null,
            Crypt_GPG::SIGN_MODE_DETACHED);

        $signatures = $this->gpg->verifyFile($filename, $signatureData);
        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileDualOnePassphrase()

    /**
     * @group file
     */
    public function testSignFileDualOnePassphrase()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename =
            $this->getTempFilename('testSignFileDualOnePassphrase.asc');

        $this->gpg->addSignKey('no-passphrase@example.com');
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->signFile($inputFilename, $outputFilename);

        $signatures = $this->gpg->verifyFile($outputFilename);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileDualNormal()

    /**
     * @group file
     */
    public function testSignFileDualNormal()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = $this->getTempFilename('testSignFileDualNormal.asc');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $this->gpg->signFile($inputFilename, $outputFilename);

        $signatures = $this->gpg->verifyFile($outputFilename);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileDualClear()

    /**
     * @group file
     */
    public function testSignFileDualClear()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = $this->getTempFilename('testSignFileDualClear.asc');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $this->gpg->signFile($inputFilename, $outputFilename,
            Crypt_GPG::SIGN_MODE_CLEAR);

        $signatures = $this->gpg->verifyFile($outputFilename);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileDualDetached()

    /**
     * @group file
     */
    public function testSignFileDualDetached()
    {
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename =
            $this->getTempFilename('testSignFileDualDetached.asc');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->addSignKey('second-keypair@example.com', 'test2');
        $this->gpg->signFile($inputFilename, $outputFilename,
            Crypt_GPG::SIGN_MODE_DETACHED);

        $signatureData = file_get_contents($outputFilename);

        $signatures = $this->gpg->verifyFile($inputFilename, $signatureData);
        $this->assertEquals(2, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testSignFileFileException_input()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testSignFileFileException_input()
    {
        // input file does not exist
        $inputFilename =
            $this->getDataFilename('testSignFileFileFileException_input.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->signFile($inputFilename);
    }

    // }}}
    // {{{ testSignFileFileException_output()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testSignFileFileException_output()
    {
        // input file is encrypted with first-keypair@example.com
        // output file does not exist
        $inputFilename  = $this->getDataFilename('testFileMedium.plain');
        $outputFilename = './non-existent' .
            '/testSignFileFileException_output.plain';

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $this->gpg->signFile($inputFilename, $outputFilename);
    }

    // }}}
    // {{{ testSignFileEmpty()

    /**
     * @group file
     */
    public function testSignFileEmpty()
    {
        $filename = $this->getDataFilename('testFileEmpty.plain');

        $this->gpg->addSignKey('first-keypair@example.com', 'test1');

        $signedData = $this->gpg->signFile($filename);
        $signatures = $this->gpg->verify($signedData);

        $this->assertEquals(1, count($signatures));
        foreach ($signatures as $signature) {
            $this->assertTrue($signature->isValid());
        }
    }

    // }}}
    // {{{ testGetLastSignatureInfo()

    public function testGetLastSignatureInfo()
    {
        $this->gpg->addSignKey('first-keypair@example.com', 'test1');
        $signedData = $this->gpg->sign('test', Crypt_GPG::SIGN_MODE_DETACHED);

        $sigInfo = $this->gpg->getLastSignatureInfo();
        $this->assertInstanceOf('Crypt_GPG_SignatureCreationInfo', $sigInfo);
        $this->assertTrue($sigInfo->isValid());
        $this->assertEquals(date('Y-m-d'), date('Y-m-d', $sigInfo->getTimestamp()));
        $this->assertEquals(Crypt_GPG::SIGN_MODE_DETACHED, $sigInfo->getMode());
        $this->assertEquals(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $sigInfo->getKeyFingerprint()
        );
        $this->assertNotNull($sigInfo->getHashAlgorithmName());
    }

    // }}}
}

?>
