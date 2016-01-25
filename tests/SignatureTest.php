<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Signature class test cases for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit SignatureTestCase
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
 * @copyright 2005-2011 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * Signature class.
 */
require_once 'Crypt/GPG/Signature.php';

/**
 * Signature class tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2010 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class SignatureTestCase extends Crypt_GPG_TestCase
{
    // construct
    // {{{ testConstructFromSignature()

    /**
     * @group construct
     */
    public function testConstructFromSignature()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature($expectedSignature);

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testConstructFromArray()

    /**
     * @group construct
     */
    public function testConstructFromArray()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $this->assertEquals('KuhELanvhPRXozEjFWb2mam1q20',
            $signature->getId());

        $this->assertEquals('8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $signature->getKeyFingerprint());

        $this->assertEquals('0C097D9EC94C06363', $signature->getKeyId());

        $this->assertEquals(1221785858, $signature->getCreationDate());
        $this->assertEquals(1421785858, $signature->getExpirationDate());

        $this->assertFalse($signature->isValid());

        $this->assertEquals('Alice <alice@example.com>',
            strval($signature->getUserId()));
    }

    // }}}

    // accessors
    // {{{ testGetId()

    /**
     * @group accessors
     */
    public function testGetId()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $this->assertEquals('KuhELanvhPRXozEjFWb2mam1q20', $signature->getId());
    }

    // }}}
    // {{{ testGetKeyFingerprint()

    /**
     * @group accessors
     */
    public function testGetKeyFingerprint()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $this->assertEquals('8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $signature->getKeyFingerprint());
    }

    // }}}
    // {{{ testGetKeyId()

    /**
     * @group accessors
     */
    public function testGetKeyId()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $this->assertEquals('0C097D9EC94C06363', $signature->getKeyId());
    }

    // }}}
    // {{{ testGetCreationDate()

    /**
     * @group accessors
     */
    public function testGetCreationDate()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $this->assertEquals(1221785858, $signature->getCreationDate());
    }

    // }}}
    // {{{ testGetExpirationDate()

    /**
     * @group accessors
     */
    public function testGetExpirationDate()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $this->assertEquals(1421785858, $signature->getExpirationDate());
    }

    // }}}
    // {{{ testIsValid()

    /**
     * @group accessors
     */
    public function testIsValid()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $this->assertTrue($signature->isValid());

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));


        $this->assertFalse($signature->isValid());
    }

    // }}}
    // {{{ testGetUserId()

    /**
     * @group accessors
     */
    public function testGetUserId()
    {
        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $expectedUserId = new Crypt_GPG_UserId(array(
            'name'  => 'Alice',
            'email' => 'alice@example.com'
        ));

        $this->assertEquals($expectedUserId, $signature->getUserId());
    }

    // }}}

    // mutators
    // {{{ testSetId()

    /**
     * @group mutators
     */
    public function testSetId()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'something different',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature->setId('KuhELanvhPRXozEjFWb2mam1q20');

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testSetKeyFingerprint()

    /**
     * @group mutators
     */
    public function testSetKeyFingerprint()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => 'bad fingerprint',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testSetKeyId()

    /**
     * @group mutators
     */
    public function testSetKeyId()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => 'bad key id',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature->setKeyId('0C097D9EC94C06363');

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testSetCreationDate()

    /**
     * @group mutators
     */
    public function testSetCreationDate()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1111111111,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature->setCreationDate(1221785858);

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testSetExpirationDate()

    /**
     * @group mutators
     */
    public function testSetExpirationDate()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 0,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature->setExpirationDate(1421785858);

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testSetValid()

    /**
     * @group mutators
     */
    public function testSetValid()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature->setValid(true);

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testSetUserId()

    /**
     * @group accessors
     */
    public function testSetUserId()
    {
        $expectedSignature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>'
        ));

        $signature = new Crypt_GPG_Signature(array(
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Bob <bob@example.com>'
        ));

        $userId = new Crypt_GPG_UserId(array(
            'name'  => 'Alice',
            'email' => 'alice@example.com'
        ));

        $signature->setUserId($userId);

        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}

    // fluent interface
    // {{{ testFluentInterface

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $signature         = new Crypt_GPG_Signature();
        $returnedSignature = $signature->setId('KuhELanvhPRXozEjFWb2mam1q20');
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setId() method.'
        );

        $signature         = new Crypt_GPG_Signature();
        $returnedSignature = $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setKeyFingerprint() ' .
            'method.'
        );

        $signature         = new Crypt_GPG_Signature();
        $returnedSignature = $signature->setKeyId('0C097D9EC94C06363');
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setKeyId() method'
        );

        $signature         = new Crypt_GPG_Signature();
        $returnedSignature = $signature->setCreationDate(1234567890);
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setCreationDate() ' .
            'method.'
        );

        $signature         = new Crypt_GPG_Signature();
        $returnedSignature = $signature->setExpirationDate(1234567890);
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setExpirationDate() ' .
            'method.'
        );

        $signature         = new Crypt_GPG_Signature();
        $returnedSignature = $signature->setValid(true);
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setValid() method.'
        );

        $signature         = new Crypt_GPG_Signature();
        $returnedSignature = $signature->setUserId(new Crypt_GPG_UserId());
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setUserId() method.'
        );
    }

    // }}}
}

?>
