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
class ExceptionsTestCase extends Crypt_GPG_TestCase
{
    // exception
    // {{{ testException

    /**
     * @group exception
     * @expectedException Crypt_GPG_Exception
     * @expectedExceptionMessage test exception
     */
    public function testException()
    {
        throw new Crypt_GPG_Exception('test exception');
    }

    // }}}

    // file exception
    // {{{ testFileException

    /**
     * @group file-exception
     * @expectedException Crypt_GPG_FileException
     * @expectedExceptionMessage test exception
     */
    public function testFileException()
    {
        throw new Crypt_GPG_FileException('test exception');
    }

    // }}}
    // {{{ testFileException_getFilename()

    /**
     * @group file-exception
     */
    public function testFileException_getFilename()
    {
        $e = new Crypt_GPG_FileException('test exception', 0,
            'test-filename.php');

        $this->assertEquals('test-filename.php', $e->getFilename());
    }

    // }}}

    // open subprocess exception
    // {{{ testOpenSubprocessException

    /**
     * @group open-subprocess-exception
     * @expectedException Crypt_GPG_OpenSubprocessException
     * @expectedExceptionMessage test exception
     */
    public function testOpenSubprocessException()
    {
        throw new Crypt_GPG_OpenSubprocessException('test exception');
    }

    // }}}
    // {{{ testOpenSubprocessException_getCommand()

    /**
     * @group open-subprocess-exception
     */
    public function testOpenSubprocessException_getCommand()
    {
        $e = new Crypt_GPG_OpenSubprocessException('test exception', 0,
            'gpg --verify');

        $this->assertEquals('gpg --verify', $e->getCommand());
    }

    // }}}

    // invalid operation exception
    // {{{ testInvalidOperationException

    /**
     * @group invalid-operation-exception
     * @expectedException Crypt_GPG_InvalidOperationException
     * @expectedExceptionMessage test exception
     */
    public function testInvalidOperationException()
    {
        throw new Crypt_GPG_InvalidOperationException('test exception');
    }

    // }}}
    // {{{ testInvalidOperationException_getOperation()

    /**
     * @group invalid-operation-exception
     */
    public function testInvalidOperationException_getOperation()
    {
        $e = new Crypt_GPG_InvalidOperationException('test exception', 0,
            '--verify');

        $this->assertEquals('--verify', $e->getOperation());
    }

    // }}}

    // key not found exception
    // {{{ testKeyNotFoundException

    /**
     * @group key-not-found-exception
     * @expectedException Crypt_GPG_KeyNotFoundException
     * @expectedExceptionMessage test exception
     */
    public function testKeyNotFoundException()
    {
        throw new Crypt_GPG_KeyNotFoundException('test exception');
    }

    // }}}
    // {{{ testKeyNotFoundException_getKeyId()

    /**
     * @group key-not-found-exception
     */
    public function testKeyNotFoundException_getKeyId()
    {
        $e = new Crypt_GPG_KeyNotFoundException('test exception', 0,
            '9F93F9116728EF12');

        $this->assertEquals('9F93F9116728EF12', $e->getKeyId());
    }

    // }}}

    // no data exception
    // {{{ testNoDataException

    /**
     * @group no-data-exception
     * @expectedException Crypt_GPG_NoDataException
     * @expectedExceptionMessage test exception
     */
    public function testNoDataException()
    {
        throw new Crypt_GPG_NoDataException('test exception');
    }

    // }}}

    // bad passphrase exception
    // {{{ testBadPassphraseException

    /**
     * @group bad-passphrase-exception
     * @expectedException Crypt_GPG_BadPassphraseException
     * @expectedExceptionMessage test exception
     */
    public function testBadPassphraseException()
    {
        throw new Crypt_GPG_BadPassphraseException('test exception');
    }

    // }}}
    // {{{ testBadPassphraseException_getBadPassphrases()

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

    // }}}
    // {{{ testBadPassphraseException_getMissingPassphrase()

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

    // }}}

    // delete private key exception
    // {{{ testDeletePrivateKeyException

    /**
     * @group delete-private-key-exception
     * @expectedException Crypt_GPG_DeletePrivateKeyException
     * @expectedExceptionMessage test exception
     */
    public function testDeletePrivateKeyException()
    {
        throw new Crypt_GPG_DeletePrivateKeyException('test exception');
    }

    // }}}
    // {{{ testDeletePrivateKeyException_getKeyId()

    /**
     * @group delete-private-key-exception
     */
    public function testDeletePrivateKeyException_getKeyId()
    {
        $e = new Crypt_GPG_DeletePrivateKeyException('test exception', 0,
            '9F93F9116728EF12');

        $this->assertEquals('9F93F9116728EF12', $e->getKeyId());
    }

    // }}}
}

?>
