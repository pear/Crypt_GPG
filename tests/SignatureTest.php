<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG\Signature;
use Crypt\GPG\UserId;

/**
 * Signature class tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2010 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class SignatureTest extends TestCase
{
    /**
     * @group construct
     */
    public function testConstructFromSignature()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature($expectedSignature);

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group construct
     */
    public function testConstructFromArray()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertEquals(
            'KuhELanvhPRXozEjFWb2mam1q20',
            $signature->getId()
        );

        $this->assertEquals(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $signature->getKeyFingerprint()
        );

        $this->assertEquals('0C097D9EC94C06363', $signature->getKeyId());

        $this->assertEquals(1221785858, $signature->getCreationDate());
        $this->assertEquals(1421785858, $signature->getExpirationDate());

        $this->assertFalse($signature->isValid());

        $this->assertEquals(
            'Alice <alice@example.com>',
            strval($signature->getUserId())
        );
    }

    /**
     * @group accessors
     */
    public function testGetId()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertEquals('KuhELanvhPRXozEjFWb2mam1q20', $signature->getId());
    }

    /**
     * @group accessors
     */
    public function testGetKeyFingerprint()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertEquals(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $signature->getKeyFingerprint()
        );
    }

    /**
     * @group accessors
     */
    public function testGetKeyId()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertEquals('0C097D9EC94C06363', $signature->getKeyId());
    }

    /**
     * @group accessors
     */
    public function testGetCreationDate()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertEquals(1221785858, $signature->getCreationDate());
    }

    /**
     * @group accessors
     */
    public function testGetExpirationDate()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertEquals(1421785858, $signature->getExpirationDate());
    }

    /**
     * @group accessors
     */
    public function testIsValid()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertTrue($signature->isValid());

        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $this->assertFalse($signature->isValid());
    }

    /**
     * @group accessors
     */
    public function testGetUserId()
    {
        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $expectedUserId = new UserId([
            'name'  => 'Alice',
            'email' => 'alice@example.com',
        ]);

        $this->assertEquals($expectedUserId, $signature->getUserId());
    }

    /**
     * @group mutators
     */
    public function testSetId()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature([
            'id'          => 'something different',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature->setId('KuhELanvhPRXozEjFWb2mam1q20');

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group mutators
     */
    public function testSetKeyFingerprint()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => 'bad fingerprint',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group mutators
     */
    public function testSetKeyId()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => '0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'keyId'       => 'bad key id',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature->setKeyId('0C097D9EC94C06363');

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group mutators
     */
    public function testSetCreationDate()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1111111111,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature->setCreationDate(1221785858);

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 0,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature->setExpirationDate(1421785858);

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group mutators
     */
    public function testSetValid()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => false,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature->setValid(true);

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group accessors
     */
    public function testSetUserId()
    {
        $expectedSignature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Alice <alice@example.com>',
        ]);

        $signature = new Signature([
            'id'          => 'KuhELanvhPRXozEjFWb2mam1q20',
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'creation'    => 1221785858,
            'expiration'  => 1421785858,
            'valid'       => true,
            'userId'      => 'Bob <bob@example.com>',
        ]);

        $userId = new UserId([
            'name'  => 'Alice',
            'email' => 'alice@example.com',
        ]);

        $signature->setUserId($userId);

        $this->assertEquals($expectedSignature, $signature);
    }

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $signature         = new Signature();
        $returnedSignature = $signature->setId('KuhELanvhPRXozEjFWb2mam1q20');
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setId() method.'
        );

        $signature         = new Signature();
        $returnedSignature = $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setKeyFingerprint() '
            . 'method.'
        );

        $signature         = new Signature();
        $returnedSignature = $signature->setKeyId('0C097D9EC94C06363');
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setKeyId() method'
        );

        $signature         = new Signature();
        $returnedSignature = $signature->setCreationDate(1234567890);
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setCreationDate() '
            . 'method.'
        );

        $signature         = new Signature();
        $returnedSignature = $signature->setExpirationDate(1234567890);
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setExpirationDate() '
            . 'method.'
        );

        $signature         = new Signature();
        $returnedSignature = $signature->setValid(true);
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setValid() method.'
        );

        $signature         = new Signature();
        $returnedSignature = $signature->setUserId(new UserId());
        $this->assertEquals(
            $signature,
            $returnedSignature,
            'Failed asserting fluent interface works for setUserId() method.'
        );
    }
}
