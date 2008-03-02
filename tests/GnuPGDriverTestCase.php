<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * PHPUnit3.2 test framework script for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit GnuPGDriverTestCase
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
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Unit tests
 */
require_once 'DriverTestCase.php';

/**
 * Tests the native GnuPG implementation of the Crypt_GPG object.
 */
class GnuPGDriverTestCase extends DriverTestCase
{
    // {{{ getDriver()

    protected function getDriver()
    {
        return 'gnupg';
    }

    // }}}
    // {{{ getOptions()

    protected function getOptions()
    {
        return array('homedir' => DriverTestCase::HOMEDIR);
    }

    // }}}
}

?>
