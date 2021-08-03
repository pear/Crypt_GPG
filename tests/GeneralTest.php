<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * General test cases for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit GeneralTestCase
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
 * @copyright 2005-2013 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * General tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2013 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class GeneralTest extends Crypt_GPG_TestCase
{
    public function testPublicKeyringFileException()
    {
        $this->expectException('Crypt_GPG_FileException');

        $publicKeyringFile = $this->getTempFilename('pubring.gpg');
        new Crypt_GPG(
            array(
                'publicKeyring' => $publicKeyringFile
            )
        );
    }

    public function testPrivateKeyringFileException()
    {
        $this->expectException('Crypt_GPG_FileException');

        $privateKeyringFile = $this->getTempFilename('secring.gpg');
        new Crypt_GPG(
            array(
                'privateKeyring' => $privateKeyringFile
            )
        );
    }

    public function testTrustDatabaseFileException()
    {
        $this->expectException('Crypt_GPG_FileException');

        $trustDbFile = $this->getTempFilename('secring.gpg');
        new Crypt_GPG(
            array(
                'trustDb' => $trustDbFile
            )
        );
    }

    public function testHomedirFileException_NoCreate()
    {
        $this->expectException('Crypt_GPG_FileException');
        $this->expectExceptionMessage('cannot be created');

        if (posix_getuid() === 0) {
            $this->markTestSkipped('Root can write to any homedir.');
        }

        $nonCreatableDirectory = '//.gnupg';
        new Crypt_GPG(array('homedir' => $nonCreatableDirectory));
    }

    public function testHomedirFileException_NoExecute()
    {
        $this->expectException('Crypt_GPG_FileException');
        $this->expectExceptionMessage('is not enterable');

        if (posix_getuid() === 0) {
            $this->markTestSkipped('Root can do what it wants to any homedir.');
        }

        $nonExecutableDirectory = $this->getTempFilename('home-no-execute');
        mkdir($nonExecutableDirectory);
        chmod($nonExecutableDirectory, 0600); // rw- --- ---

        new Crypt_GPG(array('homedir' => $nonExecutableDirectory));
    }

    public function testHomedirFileException_NoWrite()
    {
        $this->expectException('Crypt_GPG_FileException');
        $this->expectExceptionMessage('is not writable');

        if (posix_getuid() === 0) {
            $this->markTestSkipped('Root can write to any homedir.');
        }

        $nonWriteableDirectory = $this->getTempFilename('home-no-write');
        mkdir($nonWriteableDirectory);
        chmod($nonWriteableDirectory, 0500); // r-x --- ---

        new Crypt_GPG(array('homedir' => $nonWriteableDirectory));
    }

    public function testBinaryPEARException()
    {
        $this->expectException('PEAR_Exception');

        new Crypt_GPG(array('binary' => './non-existent-binary'));
    }

    public function testGPGBinaryPEARException()
    {
        $this->expectException('PEAR_Exception');

        new Crypt_GPG(array('gpgBinary' => './non-existent-binary'));
    }

    public function testSetEngine()
    {
        $engine = new Crypt_GPG_Engine($this->getOptions());
        $gpg = new Crypt_GPG();
        $gpg->setEngine($engine);

        $this->assertSame($this->getPropertyValue('Crypt_GPG', $gpg, 'engine'), $engine);
    }

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $returnedGpg = $this->gpg->setEngine(
            new Crypt_GPG_Engine($this->getOptions())
        );
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for setEngine() method.'
        );

        $returnedGpg = $this->gpg->addDecryptKey(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'test1'
        );
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for addDecryptKey() ' .
            'method.'
        );

        $returnedGpg = $this->gpg->addEncryptKey(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for addEncryptKey() ' .
            'method.'
        );

        $returnedGpg = $this->gpg->addSignKey(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'test1'
        );
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for addSignKey() ' .
            'method.'
        );

        $returnedGpg = $this->gpg->clearDecryptKeys();
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for clearDecryptKeys() ' .
            'method.'
        );

        $returnedGpg = $this->gpg->clearEncryptKeys();
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for clearEncryptKeys() ' .
            'method.'
        );

        $returnedGpg = $this->gpg->clearSignKeys();
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for clearSignKeys() ' .
            'method.'
        );
    }
}
