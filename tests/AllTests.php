<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * PHPUnit 3.2 AllTests suite for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
 * for detailed installation instructions.
 *
 * This test suite follows the PEAR AllTests conventions as documented at
 * {@link http://cvs.php.net/viewvc.cgi/pear/AllTests.php?view=markup}.
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
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

chdir(dirname(__FILE__));

if (!defined('PHPUnit_MAIN_METHOD')) {
    define('PHPUnit_MAIN_METHOD', 'Crypt_GPG_AllTests::main');
}

require_once 'PHPUnit/Framework/TestSuite.php';
require_once 'PHPUnit/TextUI/TestRunner.php';

require_once 'DecryptTestCase.php';
require_once 'DeletePublicKeyTestCase.php';
require_once 'DeletePrivateKeyTestCase.php';
require_once 'EncryptTestCase.php';
require_once 'ExportPublicKeyTestCase.php';
require_once 'GetFingerprintTestCase.php';
require_once 'GetKeysTestCase.php';
require_once 'ImportKeyTestCase.php';
require_once 'SignatureTestCase.php';
require_once 'SignTestCase.php';
require_once 'SubKeyTestCase.php';
require_once 'UserIdTestCase.php';
require_once 'VerifyTestCase.php';

/**
 * AllTests suite testing Crypt_GPG
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_AllTests
{
    // {{{ main()

    public static function main()
    {
        PHPUnit_TextUI_TestRunner::run(self::suite());
    }

    // }}}
    // {{{ suite()

    public static function suite()
    {
        $suite = new PHPUnit_Framework_TestSuite('Crypt_GPG Tests');
        $suite->addTestSuite('DecryptTestCase');
        $suite->addTestSuite('DeletePublicKeyTestCase');
        $suite->addTestSuite('DeletePrivateKeyTestCase');
        $suite->addTestSuite('EncryptTestCase');
        $suite->addTestSuite('ExportPublicKeyTestCase');
        $suite->addTestSuite('GetFingerprintTestCase');
        $suite->addTestSuite('GetKeysTestCase');
        $suite->addTestSuite('ImportKeyTestCase');
        $suite->addTestSuite('SignatureTestCase');
        $suite->addTestSuite('SignTestCase');
        $suite->addTestSuite('SubKeyTestCase');
        $suite->addTestSuite('UserIdTestCase');
        $suite->addTestSuite('VerifyTestCase');
        return $suite;
    }

    // }}}
}

if (PHPUnit_MAIN_METHOD == 'Crypt_GPG_AllTests::main') {
    Crypt_GPG_AllTests::main();
}

?>
