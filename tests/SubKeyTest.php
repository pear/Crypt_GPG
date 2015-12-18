<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Sub-key class test cases for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit SubKeyTestCase
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
 * Sub-key class.
 */
require_once 'Crypt/GPG/SubKey.php';

/**
 * Sub-key class tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2010 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class SubKeyTestCase extends Crypt_GPG_TestCase
{
    // construct
    // {{{ testConstructFromString()

    /**
     * @group construct
     */
    public function testConstructFromString()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'length'      => 2048,
            'creation'    => 1221528655,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'isRevoked'   => true
        ));

        $string = 'sub:r:2048:16:8C37DBD2A01B7976:1221528655::::::e:';
        $subKey = new Crypt_GPG_SubKey($string);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testConstructFromSubKey()

    /**
     * @group construct
     */
    public function testConstructFromSubKey()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
            'isRevoked'   => true
        ));

        $subKey = new Crypt_GPG_SubKey($expectedSubKey);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testConstructFromArray()

    /**
     * @group construct
     */
    public function testConstructFromArray()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
            'isRevoked'   => true
        ));

        $this->assertEquals('8C37DBD2A01B7976', $subKey->getId());
        $this->assertEquals(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            $subKey->getAlgorithm());

        $this->assertEquals('8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $subKey->getFingerprint());

        $this->assertEquals(2048, $subKey->getLength());
        $this->assertEquals(1221785858, $subKey->getCreationDate());
        $this->assertEquals(1421785858, $subKey->getExpirationDate());
        $this->assertFalse($subKey->canSign());
        $this->assertTrue($subKey->canEncrypt());
        $this->assertTrue($subKey->hasPrivate());
        $this->assertTrue($subKey->isRevoked());
    }

    // }}}

    // parse
    // {{{ testParse()

    /**
     * @group parse
     */
    public function testParse()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'length'      => 2048,
            'creation'    => 1221528655,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'isRevoked'   => true
        ));

        $string = 'sub:r:2048:16:8C37DBD2A01B7976:1221528655::::::e:';
        $subKey = Crypt_GPG_SubKey::parse($string);

        $this->assertEquals($expectedSubKey, $subKey);

        // test parsing 'usage' flags
        $string = 'sub:r:2048:16:8C37DBD2A01B7976:1221528655::::::esca:';
        $subKey = Crypt_GPG_SubKey::parse($string);
        $usage  = Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_ENCRYPT
            | Crypt_GPG_SubKey::USAGE_CERTIFY | Crypt_GPG_SubKey::USAGE_AUTHENTICATION;

        $this->assertEquals($usage, $subKey->usage());
    }

    // }}}
    // {{{ testParseCreationDateIso()

    /**
     * @group parse
     */
    public function testParseCreationDateIso()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'length'      => 2048,
            'creation'    => 1221442255,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true
        ));

        $string = 'sub:u:2048:16:8C37DBD2A01B7976:20080915T013055::::::e:';
        $subKey = Crypt_GPG_SubKey::parse($string);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}

    // accessors
    // {{{ testGetId()

    /**
     * @group accessors
     */
    public function testGetId()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertEquals('8C37DBD2A01B7976', $subKey->getId());
    }

    // }}}
    // {{{ testGetAlgorithm()

    /**
     * @group accessors
     */
    public function testGetAlgorithm()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertEquals(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            $subKey->getAlgorithm());
    }

    // }}}
    // {{{ testGetFingerprint()

    /**
     * @group accessors
     */
    public function testGetFingerprint()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertEquals('8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $subKey->getFingerprint());
    }

    // }}}
    // {{{ testGetLength()

    /**
     * @group accessors
     */
    public function testGetLength()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertEquals(2048, $subKey->getLength());
    }

    // }}}
    // {{{ testGetCreationDate()

    /**
     * @group accessors
     */
    public function testGetCreationDate()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertEquals(1221785858, $subKey->getCreationDate());
    }

    // }}}
    // {{{ testGetExpirationDate()

    /**
     * @group accessors
     */
    public function testGetExpirationDate()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertEquals(1421785858, $subKey->getExpirationDate());
    }

    // }}}
    // {{{ testCanSign()

    /**
     * @group accessors
     */
    public function testCanSign()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $this->assertTrue($subKey->canSign());

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertFalse($subKey->canSign());
    }

    // }}}
    // {{{ testCanEncrypt()

    /**
     * @group accessors
     */
    public function testCanEncrypt()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $this->assertTrue($subKey->canEncrypt());

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $this->assertFalse($subKey->canEncrypt());
    }

    // }}}
    // {{{ testUsage()

    /**
     * @group accessors
     */
    public function testUsage()
    {
        $usage = Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_ENCRYPT
            | Crypt_GPG_SubKey::USAGE_CERTIFY | Crypt_GPG_SubKey::USAGE_AUTHENTICATION;
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'usage'       => $usage,
            'hasPrivate'  => true
        ));

        $this->assertSame($usage, $subKey->usage());

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $this->assertSame(Crypt_GPG_SubKey::USAGE_SIGN, $subKey->usage());
    }

    // }}}
    // {{{ testHasPrivate()

    /**
     * @group accessors
     */
    public function testHasPrivate()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $this->assertTrue($subKey->hasPrivate());

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => false
        ));

        $this->assertFalse($subKey->hasPrivate());
    }

    // }}}
    // {{{ testIsRevoked()

    /**
     * @group accessors
     */
    public function testIsRevoked()
    {
        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
            'isRevoked'   => true
        ));

        $this->assertTrue($subKey->isRevoked());

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
            'isRevoked'   => false
        ));

        $this->assertFalse($subKey->isRevoked());
    }

    // }}}

    // mutators
    // {{{ testSetId()

    /**
     * @group mutators
     */
    public function testSetId()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => 'something different',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey->setId('8C37DBD2A01B7976');

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetAlgorithm()

    /**
     * @group mutators
     */
    public function testSetAlgorithm()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetFingerprint()

    /**
     * @group mutators
     */
    public function testSetFingerprint()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'something different',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey->setFingerprint('8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetLength()

    /**
     * @group mutators
     */
    public function testSetLength()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey->setLength(2048);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetCreationDate()

    /**
     * @group mutators
     */
    public function testSetCreationDate()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1111111111,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey->setCreationDate(1221785858);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetExpirationDate()

    /**
     * @group mutators
     */
    public function testSetExpirationDate()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1111111111,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey->setExpirationDate(1421785858);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetCanSign()

    /**
     * @group mutators
     */
    public function testSetCanSign()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $subKey->setCanSign(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetCanEncrypt()

    /**
     * @group mutators
     */
    public function testSetCanEncrypt()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $subKey->setCanEncrypt(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetHasPrivate()

    /**
     * @group mutators
     */
    public function testSetHasPrivate()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => false
        ));

        $subKey->setHasPrivate(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}
    // {{{ testSetRevoked()

    /**
     * @group mutators
     */
    public function testSetRevoked()
    {
        $expectedSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
            'isRevoked'   => true
        ));

        $subKey = new Crypt_GPG_SubKey(array(
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
            'isRevoked'   => false
        ));

        $subKey->setRevoked(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    // }}}

    // fluent interface
    // {{{ testFluentInterface

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setId('8C37DBD2A01B7976');
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setId() method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setAlgorithm(
            Crypt_GPG_SubKey::ALGORITHM_DSA
        );
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setAlgorithm() method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setFingerprint() ' .
            'method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setLength(2048);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setLength() method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setCreationDate(1234567890);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setCreationDate() ' .
            'method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setExpirationDate(1234567890);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setExpirationDate() ' .
            'method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setCanSign(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setCanSign() method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setCanEncrypt(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setCanEncrypt() ' .
            'method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setHasPrivate(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setHasPrivate() ' .
            'method.'
        );

        $subKey         = new Crypt_GPG_SubKey();
        $returnedSubKey = $subKey->setRevoked(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setRevoked() method.'
        );
    }

    // }}}
}

?>
