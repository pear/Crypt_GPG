<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Signing tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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
class SignTestCase extends TestCase
{
    // {{{ testSignKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group sign
     */
    public function testSignKeyNotFoundException()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'non-existent-key@example.com';
        $this->gpg->addSignKey($keyId);
        $signedData = $this->gpg->sign($data);
    }

    // }}}
    // {{{ testSignBadPassphraseException_missing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group sign
     */
    public function testSignBadPassphraseException_missing()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'public-and-private@example.com';
        $this->gpg->addSignKey($keyId);
        $signedData = $this->gpg->sign($data);
    }

    // }}}
    // {{{ testSignBadPassphraseException_bad()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group sign
     */
    public function testSignBadPassphraseException_bad()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'public-and-private@example.com';
        $passphrase = 'incorrect';
        $this->gpg->addSignKey($keyId, $passphrase);
        $signedData = $this->gpg->sign($data);
    }

    // }}}
    // {{{ testSignNoPassphrase()

    /**
     * @group sign
     */
    public function testSignNoPassphrase()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'no-passphrase@example.com';
        $this->gpg->addSignKey($keyId);
        $signedData = $this->gpg->sign($data);

        $signature = $this->gpg->verify($signedData);
        $this->assertTrue($signature->isValid());
    }

    // }}}
    // {{{ testSignNormal()

    /**
     * @group sign
     */
    public function testSignNormal()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'public-and-private@example.com';
        $passphrase = 'test';
        $this->gpg->addSignKey($keyId, $passphrase);
        $signedData = $this->gpg->sign($data);

        $signature = $this->gpg->verify($signedData);
        $this->assertTrue($signature->isValid());
    }

    // }}}
    // {{{ testSignClear()

    /**
     * @group sign
     */
    public function testSignClear()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'public-and-private@example.com';
        $passphrase = 'test';
        $this->gpg->addSignKey($keyId, $passphrase);
        $signedData = $this->gpg->sign($data, Crypt_GPG::SIGN_MODE_CLEAR);

        $signature = $this->gpg->verify($signedData);
        $this->assertTrue($signature->isValid());
    }

    // }}}
    // {{{ testSignDetached()

    /**
     * @group sign
     */
    public function testSignDetached()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $keyId = 'public-and-private@example.com';
        $passphrase = 'test';
        $this->gpg->addSignKey($keyId, $passphrase);
        $signatureData = $this->gpg->sign($data,
            Crypt_GPG::SIGN_MODE_DETACHED);

        $signature = $this->gpg->verify($data, $signatureData);
        $this->assertTrue($signature->isValid());
    }

    // }}}
}

?>
