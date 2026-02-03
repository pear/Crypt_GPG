<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * SimpleCliWrapper tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit package to be installed.
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
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Crypt/Console/SimpleCliWrapper.php';

/**
 * Tests for SimpleCliWrapper static methods.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class SimpleCliWrapperTest extends TestCase
{
    /**
     * Test getVerbosityLevel with no options provided
     */
    public function testGetVerbosityLevel_NoOptions()
    {
        $opts = [];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(0, $result);
    }

    /**
     * Test getVerbosityLevel with short option set to false (just -v)
     */
    public function testGetVerbosityLevel_ShortOptionFalse()
    {
        $opts = ['v' => false];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(0, $result);
    }

    /**
     * Test getVerbosityLevel with short option -vv (one 'v' after first)
     */
    public function testGetVerbosityLevel_ShortOptionOneV()
    {
        $opts = ['v' => 'v'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(1, $result);
    }

    /**
     * Test getVerbosityLevel with short option -vvv (two 'v's after first)
     */
    public function testGetVerbosityLevel_ShortOptionTwoVs()
    {
        $opts = ['v' => 'vv'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(2, $result);
    }

    /**
     * Test getVerbosityLevel with short option -vvvv (three 'v's after first)
     */
    public function testGetVerbosityLevel_ShortOptionThreeVs()
    {
        $opts = ['v' => 'vvv'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(3, $result);
    }

    /**
     * Test getVerbosityLevel with long option and numeric value
     */
    public function testGetVerbosityLevel_LongOptionNumeric()
    {
        $opts = ['verbose' => '3'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(3, $result);
    }

    /**
     * Test getVerbosityLevel with long option and zero value
     */
    public function testGetVerbosityLevel_LongOptionZero()
    {
        $opts = ['verbose' => '0'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(0, $result);
    }

    /**
     * Test getVerbosityLevel with long option and large numeric value
     */
    public function testGetVerbosityLevel_LongOptionLargeNumber()
    {
        $opts = ['verbose' => '10'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(10, $result);
    }

    /**
     * Test getVerbosityLevel with long option and non-numeric value
     */
    public function testGetVerbosityLevel_LongOptionNonNumeric()
    {
        $opts = ['verbose' => 'invalid'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(-1, $result);
    }

    /**
     * Test getVerbosityLevel with long option set to false
     */
    public function testGetVerbosityLevel_LongOptionFalse()
    {
        $opts = ['verbose' => false];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(-1, $result);
    }

    /**
     * Test getVerbosityLevel with both short and long options (short takes precedence)
     */
    public function testGetVerbosityLevel_BothOptions()
    {
        $opts = ['v' => 'vv', 'verbose' => '5'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(2, $result);
    }

    /**
     * Test getVerbosityLevel with short option false and long option numeric
     */
    public function testGetVerbosityLevel_ShortFalseLongNumeric()
    {
        $opts = ['v' => false, 'verbose' => '3'];
        $result = \Console\SimpleCliWrapper::getVerbosityLevel($opts);
        $this->assertEquals(0, $result);
    }

    /**
     * Test getLogLocation with no options provided
     */
    public function testGetLogLocation_NoOptions()
    {
        $opts = [];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals("", $result);
    }

    /**
     * Test getLogLocation with short option and valid path
     */
    public function testGetLogLocation_ShortOptionValidPath()
    {
        $opts = ['l' => '/path/to/log/file'];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals('/path/to/log/file', $result);
    }

    /**
     * Test getLogLocation with long option and valid path
     */
    public function testGetLogLocation_LongOptionValidPath()
    {
        $opts = ['log' => '/var/log/app.log'];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals('/var/log/app.log', $result);
    }

    /**
     * Test getLogLocation with short option and relative path
     */
    public function testGetLogLocation_ShortOptionRelativePath()
    {
        $opts = ['l' => 'logs/app.log'];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals('logs/app.log', $result);
    }

    /**
     * Test getLogLocation with both short and long options (short takes precedence)
     */
    public function testGetLogLocation_BothOptions()
    {
        $opts = ['l' => '/short/path', 'log' => '/long/path'];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals('/short/path', $result);
    }

    /**
     * Test getLogLocation with short option set to false
     */
    public function testGetLogLocation_ShortOptionFalse()
    {
        $opts = ['l' => false];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals(-1, $result);
    }

    /**
     * Test getLogLocation with long option set to false
     */
    public function testGetLogLocation_LongOptionFalse()
    {
        $opts = ['log' => false];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals(-1, $result);
    }

    /**
     * Test getLogLocation with short option as non-string (integer)
     */
    public function testGetLogLocation_ShortOptionInteger()
    {
        $opts = ['l' => 123];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals(-1, $result);
    }

    /**
     * Test getLogLocation with long option as non-string (array)
     */
    public function testGetLogLocation_LongOptionArray()
    {
        $opts = ['log' => ['path']];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals(-1, $result);
    }

    /**
     * Test getLogLocation with short option false and long option valid
     */
    public function testGetLogLocation_ShortFalseLongValid()
    {
        $opts = ['l' => false, 'log' => '/valid/path'];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals('/valid/path', $result);
    }

    /**
     * Test getLogLocation with empty string path
     */
    public function testGetLogLocation_EmptyStringPath()
    {
        $opts = ['l' => ''];
        $result = \Console\SimpleCliWrapper::getLogLocation($opts);
        $this->assertEquals('', $result);
    }
}
