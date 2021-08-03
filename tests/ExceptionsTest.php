<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Exception class test cases for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit ExceptionsTestCase
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
 * @copyright 2008-2011 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * Exception classes.
 */
require_once 'Crypt/GPG/Exceptions.php';

/**
 * Exception classes tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2011 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class ExceptionsTest extends Crypt_GPG_TestCase
{
    /**
     * @group exception
     */
    public function testException()
    {
        $this->expectException('Crypt_GPG_Exception');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_Exception('test exception');
    }

    /**
     * @group file-exception
     */
    public function testFileException()
    {
        $this->expectException('Crypt_GPG_FileException');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_FileException('test exception');
    }

    /**
     * @group file-exception
     */
    public function testFileException_getFilename()
    {
        $e = new Crypt_GPG_FileException('test exception', 0,
            'test-filename.php');

        $this->assertEquals('test-filename.php', $e->getFilename());
    }

    /**
     * @group open-subprocess-exception
     */
    public function testOpenSubprocessException()
    {
        $this->expectException('Crypt_GPG_OpenSubprocessException');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_OpenSubprocessException('test exception');
    }

    /**
     * @group open-subprocess-exception
     */
    public function testOpenSubprocessException_getCommand()
    {
        $e = new Crypt_GPG_OpenSubprocessException('test exception', 0,
            'gpg --verify');

        $this->assertEquals('gpg --verify', $e->getCommand());
    }

    /**
     * @group invalid-operation-exception
     */
    public function testInvalidOperationException()
    {
        $this->expectException('Crypt_GPG_InvalidOperationException');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_InvalidOperationException('test exception');
    }

    /**
     * @group invalid-operation-exception
     */
    public function testInvalidOperationException_getOperation()
    {
        $e = new Crypt_GPG_InvalidOperationException('test exception', 0,
            '--verify');

        $this->assertEquals('--verify', $e->getOperation());
    }

    /**
     * @group key-not-found-exception
     */
    public function testKeyNotFoundException()
    {
        $this->expectException('Crypt_GPG_KeyNotFoundException');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_KeyNotFoundException('test exception');
    }

    /**
     * @group key-not-found-exception
     */
    public function testKeyNotFoundException_getKeyId()
    {
        $e = new Crypt_GPG_KeyNotFoundException('test exception', 0,
            '9F93F9116728EF12');

        $this->assertEquals('9F93F9116728EF12', $e->getKeyId());
    }

    /**
     * @group no-data-exception
     */
    public function testNoDataException()
    {
        $this->expectException('Crypt_GPG_NoDataException');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_NoDataException('test exception');
    }

    /**
     * @group bad-passphrase-exception
     */
    public function testBadPassphraseException()
    {
        $this->expectException('Crypt_GPG_BadPassphraseException');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_BadPassphraseException('test exception');
    }

    /**
     * @group bad-passphrase-exception
     */
    public function testBadPassphraseException_getBadPassphrases()
    {
        $e = new Crypt_GPG_BadPassphraseException('test exception', 0,
            array('C097D9EC94C06363', '9F93F9116728EF12'));

        $keyIds = $e->getBadPassphrases();
        $this->assertTrue(is_array($keyIds), 'Failed to assert returned ' .
            'key ids for bad passphrases is an array.');

        $this->assertContains('C097D9EC94C06363', $keyIds);
        $this->assertContains('9F93F9116728EF12', $keyIds);
    }

    /**
     * @group bad-passphrase-exception
     */
    public function testBadPassphraseException_getMissingPassphrase()
    {
        $e = new Crypt_GPG_BadPassphraseException('test exception', 0, array(),
            array('C097D9EC94C06363', '9F93F9116728EF12'));

        $keyIds = $e->getMissingPassphrases();
        $this->assertTrue(is_array($keyIds), 'Failed to assert returned ' .
            'key ids for missing passphrases is an array.');

        $this->assertContains('C097D9EC94C06363', $keyIds);
        $this->assertContains('9F93F9116728EF12', $keyIds);
    }

    /**
     * @group delete-private-key-exception
     */
    public function testDeletePrivateKeyException()
    {
        $this->expectException('Crypt_GPG_DeletePrivateKeyException');
        $this->expectExceptionMessage('test exception');

        throw new Crypt_GPG_DeletePrivateKeyException('test exception');
    }

    /**
     * @group delete-private-key-exception
     */
    public function testDeletePrivateKeyException_getKeyId()
    {
        $e = new Crypt_GPG_DeletePrivateKeyException('test exception', 0,
            '9F93F9116728EF12');

        $this->assertEquals('9F93F9116728EF12', $e->getKeyId());
    }
}
