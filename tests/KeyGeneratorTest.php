<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key generation tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit KeyGeneratorTestCase
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
 * @version   CVS: $Id: GetKeysTestCase.php 274158 2009-01-22 06:33:54Z gauthierm $
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * The Crypt_GPG class to test
 */
require_once 'Crypt/GPG/KeyGenerator.php';

/**
 * Tests key generation of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2011 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class KeyGeneratorTest extends Crypt_GPG_TestCase
{
    protected function assertKeyEquals(
        Crypt_GPG_Key $key1,
        Crypt_GPG_Key $key2
    ) {
        $userIds1 = $key1->getUserIds();
        $userIds2 = $key2->getUserIds();
        $userId1  = $userIds1[0];
        $userId2  = $userIds2[0];
        $subKeys1 = $key1->getSubKeys();
        $subKeys2 = $key2->getSubKeys();
        $subKeyA1 = $subKeys1[0];
        $subKeyB1 = $subKeys1[1];
        $subKeyA2 = $subKeys2[0];
        $subKeyB2 = $subKeys2[1];

        $this->assertEquals(
            $userId1->getName(),
            $userId2->getName(),
            'User id names do not match.'
        );

        $this->assertEquals(
            $userId1->getEmail(),
            $userId2->getEmail(),
            'User id email addresses do not match.'
        );

        $this->assertEquals(
            $userId1->getComment(),
            $userId2->getComment(),
            'User id comments do not match.'
        );

        $this->assertEquals(
            $subKeyA1->getAlgorithm(),
            $subKeyA2->getAlgorithm(),
            'Primary key algorithms do not match.'
        );

        $this->assertEquals(
            $subKeyA1->getLength(),
            $subKeyA2->getLength(),
            'Primary key lengths do not match.'
        );

        $this->assertEquals(
            $subKeyA1->getExpirationDate(),
            $subKeyA2->getExpirationDate(),
            'Primary key expiration dates do not match.'
        );

        $this->assertEquals(
            $subKeyA1->canSign(),
            $subKeyA2->canSign(),
            'Primary key signing abilities do not match.'
        );

        $this->assertEquals(
            $subKeyA1->canEncrypt(),
            $subKeyA2->canEncrypt(),
            'Primary key encrypting abilities do not match.'
        );

        $this->assertEquals(
            $subKeyA1->hasPrivate(),
            $subKeyA2->hasPrivate(),
            'Primary key private keys do not match.'
        );

        $this->assertEquals(
            $subKeyB1->getAlgorithm(),
            $subKeyB2->getAlgorithm(),
            'Secondary key algorithms do not match.'
        );

        $this->assertEquals(
            $subKeyB1->getLength(),
            $subKeyB2->getLength(),
            'Secondary key lengths do not match.'
        );

        $this->assertEquals(
            $subKeyB1->getExpirationDate(),
            $subKeyB2->getExpirationDate(),
            'Secondary key expiration dates do not match.'
        );

        $this->assertEquals(
            $subKeyB1->canSign(),
            $subKeyB2->canSign(),
            'Secondary key signing abilities do not match.'
        );

        $this->assertEquals(
            $subKeyB1->canEncrypt(),
            $subKeyB2->canEncrypt(),
            'Secondary key encrypting abilities do not match.'
        );

        $this->assertEquals(
            $subKeyB1->hasPrivate(),
            $subKeyB2->hasPrivate(),
            'Secondary key private keys do not match.'
        );
    }

    public function setUp(): void
    {
        parent::setUp();
        $this->generator = new Crypt_GPG_KeyGenerator($this->getOptions());
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate_zero()
    {
        $expectedDate = 0;
        $this->generator->setExpirationDate(0);

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'expirationDate');
        $this->assertSame($expectedDate, $value, 'Setting expiration date to zero failed.');
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate_integer()
    {
        $expectedDate = 2000000000;
        $this->generator->setExpirationDate(2000000000);

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'expirationDate');
        $this->assertSame($expectedDate, $value, 'Setting expiration date by integer failed.');
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate_string()
    {
        date_default_timezone_set('UTC');

        $expectedDate = 2000000000;
        $this->generator->setExpirationDate('2033-05-18T03:33:20');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'expirationDate');
        $this->assertSame($expectedDate, $value, 'Setting expiration date by string failed.');
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate_invalid_format()
    {
        $this->expectException('InvalidArgumentException');

        date_default_timezone_set('UTC');

        $this->generator->setExpirationDate('this is not a date');
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate_too_early_date()
    {
        $this->expectException('InvalidArgumentException');

        $this->generator->setExpirationDate(1301088055);
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate_today()
    {
        $this->expectException('InvalidArgumentException');

        $this->generator->setExpirationDate(time());
    }

    /**
     * @group mutators
     */
    public function testSetExpirationDate_too_late_date()
    {
        $this->expectException('InvalidArgumentException');

        $this->generator->setExpirationDate(2147483648);
    }

    /**
     * @group mutators
     */
    public function testSetPassphrase()
    {
        $expectedPassphrase = 'test1';
        $this->generator->setPassphrase('test1');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'passphrase');
        $this->assertSame($expectedPassphrase, $value, 'Setting passphrase failed.');
    }

    /**
     * @group mutators
     */
    public function testSetKeyParams_algorithm()
    {
        $expectedAlgorithm = Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN;
        $expectedSize      = 1024;
        $expectedUsage     = Crypt_GPG_SubKey::USAGE_SIGN
            | Crypt_GPG_SubKey::USAGE_CERTIFY;

        $this->generator->setKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN
        );

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keyAlgorithm');
        $this->assertSame($expectedAlgorithm, $value, 'Setting key algorithm failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keySize');
        $this->assertSame($expectedSize, $value, 'Setting key algorithm changed key size.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keyUsage');
        $this->assertSame($expectedUsage, $value, 'Setting key algorithm changed key usage.');
    }

    /**
     * @group mutators
     */
    public function testSetKeyParams_algorithm_and_size()
    {
        $expectedAlgorithm = Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN;
        $expectedSize      = 512;
        $expectedUsage     = Crypt_GPG_SubKey::USAGE_SIGN
            | Crypt_GPG_SubKey::USAGE_CERTIFY;

        $this->generator->setKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN,
            512
        );


        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keyAlgorithm');
        $this->assertSame($expectedAlgorithm, $value, 'Setting key algorithm failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keySize');
        $this->assertSame($expectedSize, $value, 'Setting key size failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keyUsage');
        $this->assertSame($expectedUsage, $value, 'Setting key algorithm and size changed key usage.');
    }

    /**
     * @group mutators
     */
    public function testSetKeyParams_algorithm_size_and_usage()
    {
        $expectedAlgorithm = Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN;
        $expectedSize      = 512;
        $expectedUsage     = Crypt_GPG_SubKey::USAGE_SIGN
            | Crypt_GPG_SubKey::USAGE_CERTIFY
            | Crypt_GPG_SubKey::USAGE_ENCRYPT;

        $this->generator->setKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN,
            512,
              Crypt_GPG_SubKey::USAGE_SIGN
            | Crypt_GPG_SubKey::USAGE_CERTIFY
            | Crypt_GPG_SubKey::USAGE_ENCRYPT
        );


        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keyAlgorithm');
        $this->assertSame($expectedAlgorithm, $value, 'Setting key algorithm failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keySize');
        $this->assertSame($expectedSize, $value, 'Setting key size failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'keyUsage');
        $this->assertSame($expectedUsage, $value, 'Setting key algorithm and size changed key usage.');
    }

    /**
     * @group mutators
     */
    public function testSetKeyParams_invalid_algorithm()
    {
        $this->expectException('Crypt_GPG_InvalidKeyParamsException');

        $this->generator->setKeyParams(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
    }

    /**
     * @group mutators
     */
    public function testSetKeyParams_invalid_dsa_usage()
    {
        $this->expectException('Crypt_GPG_InvalidKeyParamsException');

        $this->generator->setKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_DSA,
            2048,
            Crypt_GPG_SubKey::USAGE_ENCRYPT | Crypt_GPG_SubKey::USAGE_CERTIFY
        );
    }

    /**
     * @group mutators
     */
    public function testSetSubKeyParams_algorithm()
    {
        $expectedAlgorithm = Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN;
        $expectedSize      = 2048;
        $expectedUsage     = Crypt_GPG_SubKey::USAGE_ENCRYPT;

        $this->generator->setSubKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN
        );

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeyAlgorithm');
        $this->assertSame($expectedAlgorithm, $value, 'Setting sub-key algorithm failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeySize');
        $this->assertSame($expectedSize, $value, 'Setting sub-key algorithm changed key size.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeyUsage');
        $this->assertSame($expectedUsage, $value, 'Setting sub-key algorithm changed key usage.');
    }

    /**
     * @group mutators
     */
    public function testSetSubKeyParams_algorithm_and_size()
    {
        $expectedAlgorithm = Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN;
        $expectedSize      = 1024;
        $expectedUsage     = Crypt_GPG_SubKey::USAGE_ENCRYPT;

        $this->generator->setSubKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN,
            1024
        );

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeyAlgorithm');
        $this->assertSame($expectedAlgorithm, $value, 'Setting sub-key algorithm failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeySize');
        $this->assertSame($expectedSize, $value, 'Setting sub-key algorithm changed key size.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeyUsage');
        $this->assertSame($expectedUsage, $value, 'Setting sub-key algorithm changed key usage.');
    }

    /**
     * @group mutators
     */
    public function testSetSubKeyParams_algorithm_size_and_usage()
    {
        $expectedAlgorithm = Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN;
        $expectedSize      = 1024;
        $expectedUsage     = Crypt_GPG_SubKey::USAGE_SIGN
            | Crypt_GPG_SubKey::USAGE_ENCRYPT;

        $this->generator->setSubKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN,
            1024,
              Crypt_GPG_SubKey::USAGE_SIGN
            | Crypt_GPG_SubKey::USAGE_ENCRYPT
        );

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeyAlgorithm');
        $this->assertSame($expectedAlgorithm, $value, 'Setting sub-key algorithm failed.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeySize');
        $this->assertSame($expectedSize, $value, 'Setting sub-key algorithm changed key size.');

        $value = $this->getPropertyValue('Crypt_GPG_KeyGenerator', $this->generator, 'subKeyUsage');
        $this->assertSame($expectedUsage, $value, 'Setting sub-key algorithm changed key usage.');
    }

    /**
     * @group mutators
     */
    public function testSetSubKeyParams_invalid_elgamal_usage()
    {
        $this->expectException('Crypt_GPG_InvalidKeyParamsException');

        $this->generator->setSubKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            2048,
            Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_ENCRYPT
        );
    }

    /**
     * @group mutators
     */
    public function testSetSubKeyParams_invalid_dsa_usage()
    {
        $this->expectException('Crypt_GPG_InvalidKeyParamsException');

        $this->generator->setSubKeyParams(
            Crypt_GPG_SubKey::ALGORITHM_DSA,
            2048,
            Crypt_GPG_SubKey::USAGE_SIGN | Crypt_GPG_SubKey::USAGE_ENCRYPT
        );
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithName()
    {
        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        // {{{ generate-test@example.com
        $expectedKey = new Crypt_GPG_Key();

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Test Keypair');
        $expectedKey->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setLength(1024);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(true);
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setLength(2048);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);
        // }}}

        $key = $this->generator->generateKey('Test Keypair');

        $this->assertKeyEquals($expectedKey, $key);
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithNameAndEmail()
    {
        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        // {{{ generate-test@example.com
        $expectedKey = new Crypt_GPG_Key();

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Test Keypair');
        $userId->setEmail('generate-test@example.com');
        $expectedKey->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setLength(1024);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(true);
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setLength(2048);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);
        // }}}

        $key = $this->generator->generateKey(
            'Test Keypair',
            'generate-test@example.com'
        );

        $this->assertKeyEquals($expectedKey, $key);
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithNameEmailAndComment()
    {
        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        // {{{ generate-test@example.com
        $expectedKey = new Crypt_GPG_Key();

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Test Keypair');
        $userId->setComment('do not use this key');
        $userId->setEmail('generate-test@example.com');
        $expectedKey->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setLength(1024);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(true);
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setLength(2048);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);
        // }}}

        $key = $this->generator->generateKey(
            'Test Keypair',
            'generate-test@example.com',
            'do not use this key'
        );

        $this->assertKeyEquals($expectedKey, $key);
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithUserId()
    {
        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        // {{{ generate-test@example.com
        $expectedKey = new Crypt_GPG_Key();

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Test Keypair');
        $userId->setEmail('generate-test@example.com');
        $expectedKey->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setLength(1024);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(true);
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setLength(2048);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);
        // }}}

        $key = $this->generator->generateKey(
            new Crypt_GPG_UserId(
                'Test Keypair <generate-test@example.com>'
            )
        );

        $this->assertKeyEquals($expectedKey, $key);
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithPassphrase()
    {
        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        // {{{ generate-test@example.com
        $expectedKey = new Crypt_GPG_Key();

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Test Keypair');
        $userId->setEmail('generate-test@example.com');
        $expectedKey->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setLength(1024);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(true);
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setLength(2048);
        $subKey->setExpirationDate(0);
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);
        // }}}

        $key = $this->generator->setPassphrase('test1')->generateKey(
            new Crypt_GPG_UserId(
                'Test Keypair <generate-test@example.com>'
            )
        );

        $this->assertKeyEquals($expectedKey, $key);
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithExpirationDate()
    {
        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        // {{{ generate-test@example.com
        $expectedKey = new Crypt_GPG_Key();

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Test Keypair');
        $userId->setEmail('generate-test@example.com');
        $expectedKey->addUserId($userId);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $subKey->setLength(1024);
        $subKey->setExpirationDate(1999998000); // truncated to day
        $subKey->setCanSign(true);
        $subKey->setCanEncrypt(false);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey();
        $subKey->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $subKey->setLength(2048);
        $subKey->setExpirationDate(1999998000); // truncated to day
        $subKey->setCanSign(false);
        $subKey->setCanEncrypt(true);
        $subKey->setHasPrivate(true);
        $expectedKey->addSubKey($subKey);
        // }}}

        $key = $this->generator->setExpirationDate(2000000000)->generateKey(
            new Crypt_GPG_UserId(
                'Test Keypair <generate-test@example.com>'
            )
        );

        // @TODO: I've got difference in expiration dates here

        $this->assertKeyEquals($expectedKey, $key);
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithInvalidPrimaryKeyAlgorithm()
    {
        $this->expectException('Crypt_GPG_InvalidKeyParamsException');

        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        $key = $this->generator
            ->setKeyParams(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN)
            ->generateKey(
                new Crypt_GPG_UserId(
                    'Test Keypair <generate-test@example.com>'
                )
            );
    }

    /**
     * @group generate-key
     */
    public function testGenerateKeyWithInvalidSubKeyAlgorithm()
    {
        $this->expectException('Crypt_GPG_InvalidKeyParamsException');

        if (!$this->config['enable-key-generation']) {
            $this->markTestSkipped(
                'Key generation tests are disabled. To run key generation '
                . 'tests, enable them in the test configuration. See the '
                . 'configuration in \'config.php.dist\' for an exampe.'
            );
        }

        $key = $this->generator
            ->setSubKeyParams(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC_SGN)
            ->generateKey(
                new Crypt_GPG_UserId(
                    'Test Keypair <generate-test@example.com>'
                )
            );
    }
}
