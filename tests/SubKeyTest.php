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
 * @link      http://pear.php.net/package/Crypt_GPG
 */

namespace Crypt\GPG\Tests;

use Crypt\GPG\SubKey;
use Crypt\GPG\UserId;

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
class SubKeyTest extends TestCase
{
    /**
     * @group construct
     */
    public function testConstructFromString()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'length'      => 2048,
            'creation'    => 1221528655,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'isRevoked'   => true,
        ]);

        $string = 'sub:r:2048:16:8C37DBD2A01B7976:1221528655::::::e:';
        $subKey = new SubKey($string);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group construct
     */
    public function testConstructFromSubKey()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
            'isRevoked'   => true,
        ]);

        $subKey = new SubKey($expectedSubKey);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group construct
     */
    public function testConstructFromArray()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 3321785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
            'isRevoked'   => true,
        ]);

        $this->assertEquals('8C37DBD2A01B7976', $subKey->getId());
        $this->assertEquals(
            SubKey::ALGORITHM_ELGAMAL_ENC,
            $subKey->getAlgorithm()
        );

        $this->assertEquals(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $subKey->getFingerprint()
        );

        $this->assertEquals(2048, $subKey->getLength());
        $this->assertFalse($subKey->canSign());
        $this->assertTrue($subKey->canEncrypt());
        $this->assertTrue($subKey->hasPrivate());
        $this->assertTrue($subKey->isRevoked());
        $this->assertSame('2008-09-19T00:57:38+00:00', $subKey->getCreationDateTime()->format('c'));
        $this->assertSame('2075-04-06T14:17:38+00:00', $subKey->getExpirationDateTime()->format('c'));
        $this->assertSame(1221785858, $subKey->getCreationDate());

        // will fail on 32-bit
        if (PHP_INT_MAX > 2147483647) {
            $this->assertSame(3321785858, $subKey->getExpirationDate());
        }
    }

    /**
     * @group parse
     */
    public function testParse()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'length'      => 2048,
            'creation'    => 1221528655,
            'expiration'  => 3321785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'isRevoked'   => true,
        ]);

        $string = 'sub:r:2048:16:8C37DBD2A01B7976:1221528655:3321785858:::::e:';
        $subKey = SubKey::parse($string);

        $this->assertEquals($expectedSubKey, $subKey);

        // test parsing 'usage' flags
        $string = 'sub:r:2048:16:8C37DBD2A01B7976:1221528655::::::esca:';
        $subKey = SubKey::parse($string);
        $usage  = SubKey::USAGE_SIGN | SubKey::USAGE_ENCRYPT
            | SubKey::USAGE_CERTIFY | SubKey::USAGE_AUTHENTICATION;

        $this->assertEquals($usage, $subKey->usage());
    }

    /**
     * @group parse
     */
    public function testParseCreationDateIso()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'length'      => 2048,
            'creation'    => 1221442255,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
        ]);

        $string = 'sub:u:2048:16:8C37DBD2A01B7976:20080915T013055::::::e:';
        $subKey = SubKey::parse($string);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group accessors
     */
    public function testGetId()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertEquals('8C37DBD2A01B7976', $subKey->getId());
    }

    /**
     * @group accessors
     */
    public function testGetAlgorithm()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertEquals(
            SubKey::ALGORITHM_ELGAMAL_ENC,
            $subKey->getAlgorithm()
        );
    }

    /**
     * @group accessors
     */
    public function testGetFingerprint()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertEquals(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $subKey->getFingerprint()
        );
    }

    /**
     * @group accessors
     */
    public function testGetLength()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertEquals(2048, $subKey->getLength());
    }

    /**
     * @group accessors
     */
    public function testGetCreationDate()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertEquals(1221785858, $subKey->getCreationDate());
    }

    /**
     * @group accessors
     */
    public function testGetCreationDateTime()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertSame('2008-09-19T00:57:38+00:00', $subKey->getCreationDateTime()->format('c'));

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 0,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertSame(null, $subKey->getCreationDateTime());
    }

    /**
     * @group accessors
     */
    public function testGetExpirationDate()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertEquals(1421785858, $subKey->getExpirationDate());
    }

    /**
     * @group accessors
     */
    public function testGetExpirationDateTime()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertSame('2015-01-20T20:30:58+00:00', $subKey->getExpirationDateTime()->format('c'));

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 0,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertSame(null, $subKey->getExpirationDateTime());
    }

    /**
     * @group accessors
     */
    public function testCanSign()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $this->assertTrue($subKey->canSign());

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertFalse($subKey->canSign());
    }

    /**
     * @group accessors
     */
    public function testCanEncrypt()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $this->assertTrue($subKey->canEncrypt());

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $this->assertFalse($subKey->canEncrypt());
    }

    /**
     * @group accessors
     */
    public function testUsage()
    {
        $usage = SubKey::USAGE_SIGN | SubKey::USAGE_ENCRYPT
            | SubKey::USAGE_CERTIFY | SubKey::USAGE_AUTHENTICATION;
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'usage'       => $usage,
            'hasPrivate'  => true,
        ]);

        $this->assertSame($usage, $subKey->usage());

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $this->assertSame(SubKey::USAGE_SIGN, $subKey->usage());
    }

    /**
     * @group accessors
     */
    public function testHasPrivate()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $this->assertTrue($subKey->hasPrivate());

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
        ]);

        $this->assertFalse($subKey->hasPrivate());
    }

    /**
     * @group accessors
     */
    public function testIsRevoked()
    {
        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
            'isRevoked'   => true,
        ]);

        $this->assertTrue($subKey->isRevoked());

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
            'isRevoked'   => false,
        ]);

        $this->assertFalse($subKey->isRevoked());
    }

    /**
     * @group mutators
     */
    public function testSetId()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => 'something different',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey->setId('8C37DBD2A01B7976');

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetAlgorithm()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey->setAlgorithm(SubKey::ALGORITHM_ELGAMAL_ENC);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetFingerprint()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'something different',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey->setFingerprint('8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetLength()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey->setLength(2048);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetCreationDate()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1111111111,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey->setCreationDate(1221785858);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1111111111,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey->setExpirationDate(1421785858);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetCanSign()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $subKey->setCanSign(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetCanEncrypt()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $subKey->setCanEncrypt(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetHasPrivate()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
        ]);

        $subKey->setHasPrivate(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group mutators
     */
    public function testSetRevoked()
    {
        $expectedSubKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
            'isRevoked'   => true,
        ]);

        $subKey = new SubKey([
            'id'          => '8C37DBD2A01B7976',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 2048,
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'canSign'     => false,
            'canEncrypt'  => false,
            'hasPrivate'  => false,
            'isRevoked'   => false,
        ]);

        $subKey->setRevoked(true);

        $this->assertEquals($expectedSubKey, $subKey);
    }

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setId('8C37DBD2A01B7976');
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setId() method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setAlgorithm(SubKey::ALGORITHM_DSA);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setAlgorithm() method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setFingerprint() '
            . 'method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setLength(2048);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setLength() method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setCreationDate(1234567890);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setCreationDate() '
            . 'method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setExpirationDate(1234567890);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setExpirationDate() '
            . 'method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setCanSign(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setCanSign() method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setCanEncrypt(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setCanEncrypt() '
            . 'method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setHasPrivate(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setHasPrivate() '
            . 'method.'
        );

        $subKey         = new SubKey();
        $returnedSubKey = $subKey->setRevoked(true);
        $this->assertEquals(
            $subKey,
            $returnedSubKey,
            'Failed asserting fluent interface works for setRevoked() method.'
        );
    }
}
