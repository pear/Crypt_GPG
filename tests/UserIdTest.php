<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * User id class test cases for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit UserIdTestCase
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
 * @copyright 2008-2010 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * User Id class.
 */
require_once 'Crypt/GPG/UserId.php';

/**
 * User id class tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2010 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class UserIdTestCase extends Crypt_GPG_TestCase
{
    // construct
    // {{{ testConstructFromString()

    /**
     * @group construct
     */
    public function testConstructFromString()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment',
            'email'   => 'test@example.com'
        ));

        $string = 'Example User (This is a test comment) <test@example.com>';
        $userId = new Crypt_GPG_UserId($string);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testConstructFromUserId()

    /**
     * @group construct
     */
    public function testConstructFromUserId()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment',
            'email'   => 'test@example.com',
            'revoked' => true,
            'valid'   => false
        ));

        $userId = new Crypt_GPG_UserId($expectedUserId);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testConstructFromArray()

    /**
     * @group construct
     */
    public function testConstructFromArray()
    {
        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment',
            'email'   => 'test@example.com',
            'revoked' => true,
            'valid'   => false
        ));

        $this->assertEquals('Example User',           $userId->getName());
        $this->assertEquals('This is a test comment', $userId->getComment());
        $this->assertEquals('test@example.com',       $userId->getEmail());

        $this->assertTrue($userId->isRevoked());

        $this->assertFalse($userId->isValid());
    }

    // }}}

    // parse
    // {{{ testParseFull()

    /**
     * @group parse
     */
    public function testParseFull()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment',
            'email'   => 'test@example.com'
        ));

        $string = 'Example User (This is a test comment) <test@example.com>';
        $userId = Crypt_GPG_UserId::parse($string);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testParseNameOnly()

    /**
     * @group parse
     */
    public function testParseNameOnly()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name' => 'Example User'
        ));

        $string = 'Example User';
        $userId = Crypt_GPG_UserId::parse($string);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testParseNameComment()

    /**
     * @group parse
     */
    public function testParseNameComment()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment'
        ));

        $string = 'Example User (This is a test comment)';
        $userId = Crypt_GPG_UserId::parse($string);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testParseNameEmail()

    /**
     * @group parse
     */
    public function testParseNameEmail()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'email' => 'test@example.com'
        ));

        $string = 'Example User <test@example.com>';
        $userId = Crypt_GPG_UserId::parse($string);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testParseEmailOnly()

    /**
     * @group parse
     */
    public function testParseEmailOnly()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'  => '',
            'email' => 'test@example.com'
        ));

        $string = '<test@example.com>';
        $userId = Crypt_GPG_UserId::parse($string);

        $this->assertEquals($expectedUserId, $userId);

        $string = 'test@example.com';
        $userId = Crypt_GPG_UserId::parse($string);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}

    // to-string
    // {{{ testToStringFull()

    /**
     * @group to-string
     */
    public function testToStringFull()
    {
        $expected = 'Example User (This is a test comment) <test@example.com>';

        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment',
            'email'   => 'test@example.com'
        ));

        $string = strval($userId);
        $this->assertEquals($expected, $string);
    }

    // }}}
    // {{{ testToStringNameOnly()

    /**
     * @group to-string
     */
    public function testToStringNameOnly()
    {
        $expected = 'Example User';

        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
        ));

        $string = strval($userId);
        $this->assertEquals($expected, $string);
    }

    // }}}
    // {{{ testToStringNameComment()

    /**
     * @group to-string
     */
    public function testToStringNameComment()
    {
        $expected = 'Example User (This is a test comment)';

        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment',
        ));

        $string = strval($userId);
        $this->assertEquals($expected, $string);
    }

    // }}}
    // {{{ testToStringNameEmail()

    /**
     * @group to-string
     */
    public function testToStringNameEmail()
    {
        $expected = 'Example User <test@example.com>';

        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'email'   => 'test@example.com'
        ));

        $string = strval($userId);
        $this->assertEquals($expected, $string);
    }

    // }}}

    // accessors
    // {{{ testGetName()

    /**
     * @group accessors
     */
    public function testGetName()
    {
        $userId = new Crypt_GPG_UserId(array(
            'name' => 'Example User'
        ));

        $this->assertEquals('Example User', $userId->getName());
    }

    // }}}
    // {{{ testGetComment()

    /**
     * @group accessors
     */
    public function testGetComment()
    {
        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'This is a test comment'
        ));

        $this->assertEquals('This is a test comment', $userId->getComment());
    }

    // }}}
    // {{{ testGetEmail()

    /**
     * @group accessors
     */
    public function testGetEmail()
    {
        $userId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'email' => 'test@example.com'
        ));

        $this->assertEquals('test@example.com', $userId->getEmail());
    }

    // }}}
    // {{{ testIsRevoked()

    /**
     * @group accessors
     */
    public function testIsRevoked()
    {
        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'revoked' => true,
        ));

        $this->assertTrue($userId->isRevoked());

        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'revoked' => false,
        ));

        $this->assertFalse($userId->isRevoked());
    }

    // }}}
    // {{{ testIsValid()

    /**
     * @group accessors
     */
    public function testIsValid()
    {
        $userId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'valid' => true,
        ));

        $this->assertTrue($userId->isValid());

        $userId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'valid' => false,
        ));

        $this->assertFalse($userId->isValid());
    }

    // }}}

    // mutators
    // {{{ testSetName()

    /**
     * @group mutators
     */
    public function testSetName()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name' => 'Second Name'
        ));

        $userId = new Crypt_GPG_UserId(array(
            'name' => 'First Name'
        ));

        $userId->setName('Second Name');

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testSetComment()

    /**
     * @group mutators
     */
    public function testSetComment()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'Second comment text'
        ));

        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'comment' => 'First comment text'
        ));

        $userId->setComment('Second comment text');

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testSetEmail()

    /**
     * @group mutators
     */
    public function testSetEmail()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'email' => 'second@example.com'
        ));

        $userId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'email' => 'first@example.com'
        ));

        $userId->setEmail('second@example.com');

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testSetRevoked()

    /**
     * @group mutators
     */
    public function testSetRevoked()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'revoked' => true,
        ));

        $userId = new Crypt_GPG_UserId(array(
            'name'    => 'Example User',
            'revoked' => false,
        ));

        $userId->setRevoked(true);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}
    // {{{ testSetValid()

    /**
     * @group mutators
     */
    public function testSetValid()
    {
        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'valid' => true,
        ));

        $userId = new Crypt_GPG_UserId(array(
            'name'  => 'Example User',
            'valid' => false,
        ));

        $userId->setValid(true);

        $this->assertEquals($expectedUserId, $userId);
    }

    // }}}

    // fluent interface
    // {{{ testFluentInterface

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $userId         = new Crypt_GPG_UserId();
        $returnedUserId = $userId->setName('Alice');
        $this->assertEquals(
            $userId,
            $returnedUserId,
            'Failed asserting fluent interface works for setName() method.'
        );

        $userId         = new Crypt_GPG_UserId();
        $returnedUserId = $userId->setComment('encryption is fun');
        $this->assertEquals(
            $userId,
            $returnedUserId,
            'Failed asserting fluent interface works for setComment() method.'
        );

        $userId         = new Crypt_GPG_UserId();
        $returnedUserId = $userId->setEmail('test@example.com');
        $this->assertEquals(
            $userId,
            $returnedUserId,
            'Failed asserting fluent interface works for setEmail() method.'
        );

        $userId         = new Crypt_GPG_UserId();
        $returnedUserId = $userId->setRevoked(true);
        $this->assertEquals(
            $userId,
            $returnedUserId,
            'Failed asserting fluent interface works for setRevoked() method.'
        );

        $userId         = new Crypt_GPG_UserId();
        $returnedUserId = $userId->setValid(true);
        $this->assertEquals(
            $userId,
            $returnedUserId,
            'Failed asserting fluent interface works for setValid() method.'
        );
    }

    // }}}
}

?>
