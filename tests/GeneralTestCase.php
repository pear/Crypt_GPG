<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * General test cases for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
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
 * General tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class GeneralTestCase extends Crypt_GPG_TestCase
{
    // {{{ testPublicKeyringFileException()

    /**
     * @expectedException Crypt_GPG_FileException
     */
    public function testPublicKeyringFileException()
    {
        $publicKeyringFile = $this->getTempFilename('pubring.gpg');
        new Crypt_GPG(
            array(
                'publicKeyring' => $publicKeyringFile
            )
        );
    }

    // }}}
    // {{{ testPrivateKeyringFileException()

    /**
     * @expectedException Crypt_GPG_FileException
     */
    public function testPrivateKeyringFileException()
    {
        $privateKeyringFile = $this->getTempFilename('secring.gpg');
        new Crypt_GPG(
            array(
                'privateKeyring' => $privateKeyringFile
            )
        );
    }

    // }}}
    // {{{ testTrustDatabaseFileException()

    /**
     * @expectedException Crypt_GPG_FileException
     */
    public function testTrustDatabaseFileException()
    {
        $trustDbFile = $this->getTempFilename('secring.gpg');
        new Crypt_GPG(
            array(
                'trustDb' => $trustDbFile
            )
        );
    }

    // }}}
    // {{{ testHomedirFileException()

    /**
     * @expectedException Crypt_GPG_FileException
     */
    public function testHomedirFileException()
    {
        if (posix_getuid() === 0) {
            $this->markTestSkipped('Root can write to any homedir.');
        }

        $nonWriteableDirectory = '//.gnupg';
        new Crypt_GPG(array('homedir' => $nonWriteableDirectory));
    }

    // }}}
    // {{{ testBinaryPEARException()

    /**
     * @expectedException PEAR_Exception
     */
    public function testBinaryPEARException()
    {
        new Crypt_GPG(array('binary' => './non-existent-binary'));
    }

    // }}}
    // {{{ testGPGBinaryPEARException()

    /**
     * @expectedException PEAR_Exception
     */
    public function testGPGBinaryPEARException()
    {
        new Crypt_GPG(array('gpgBinary' => './non-existent-binary'));
    }

    // }}}
    // {{{ testSetEngine()

    public function testSetEngine()
    {
        $engine = new Crypt_GPG_Engine($this->getOptions());
        $gpg = new Crypt_GPG();
        $gpg->setEngine($engine);

        $homedirConstraint = $this->attribute(
            $this->attributeEqualTo(
                '_homedir',
                dirname(__FILE__) . '/' . self::HOMEDIR
            ),
            'engine'
        );

        $this->assertThat(
            $gpg,
            $homedirConstraint,
            'Engine was not set properly.'
        );
    }

    // }}}
}

?>
