<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key class test cases for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit KeyTestCase
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
 * Key class.
 */
require_once 'Crypt/GPG/Key.php';

/**
 * User id class.
 */
require_once 'Crypt/GPG/UserId.php';

/**
 * Sub-key class.
 */
require_once 'Crypt/GPG/SubKey.php';

/**
 * Key class tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2010 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class KeyTestCase extends Crypt_GPG_TestCase
{
    // accessors
    // {{{ testGetSubKeys()

    /**
     * @group accessors
     */
    public function testGetSubKeys()
    {
        $key = new Crypt_GPG_Key();

        $firstSubKey = new Crypt_GPG_SubKey(array(
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $key->addSubKey($firstSubKey);

        $secondSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '9F93F9116728EF12',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'C9C65B3BBF040E40D0EA27B79F93F9116728EF12',
            'length'      => 2048,
            'creation'    => 1221785821,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $key->addSubKey($secondSubKey);

        $subKeys = $key->getSubKeys();
        $this->assertTrue(is_array($subKeys),
            'Failed to assert returned sub-keys is an array.');

        $this->assertEquals(2, count($subKeys),
            'Failed to assert number of returned sub-keys is the same as ' .
            'the number of sub-keys added.');

        $this->assertContainsOnly('Crypt_GPG_SubKey', $subKeys, false,
            'Failed to assert all returned sub-keys are Crypt_GPG_SubKey ' .
            'objects.');

        $this->assertArrayHasKey(0, $subKeys);
        $this->assertEquals($subKeys[0], $firstSubKey,
            'Failed to assert the first sub-key is the same as the first ' .
            'added sub-key.');

        $this->assertArrayHasKey(1, $subKeys);
        $this->assertEquals($subKeys[1], $secondSubKey,
            'Failed to assert the second sub-key is the same as the second ' .
            'added sub-key.');
    }

    // }}}
    // {{{ testGetUserIds()

    /**
     * @group accessors
     */
    public function testGetUserIds()
    {
        $key = new Crypt_GPG_Key();

        $firstUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com'
        ));

        $key->addUserId($firstUserId);

        $secondUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Bob',
            'comment' => 'receiving',
            'email'   => 'bob@example.com'
        ));

        $key->addUserId($secondUserId);

        $userIds = $key->getUserIds();
        $this->assertTrue(is_array($userIds),
            'Failed to assert returned user ids is an array.');

        $this->assertEquals(2, count($userIds),
            'Failed to assert number of returned user ids is the same as ' .
            'the number of user ids added.');

        $this->assertContainsOnly('Crypt_GPG_UserId', $userIds, false,
            'Failed to assert all returned user ids are Crypt_GPG_UserId ' .
            'objects.');

        $this->assertArrayHasKey(0, $userIds);
        $this->assertEquals($userIds[0], $firstUserId,
            'Failed to assert the first user id is the same as the first ' .
            'added user id.');

        $this->assertArrayHasKey(1, $userIds);
        $this->assertEquals($userIds[1], $secondUserId,
            'Failed to assert the second user id is the same as the second ' .
            'added user id.');
    }

    // }}}
    // {{{ testGetPrimaryKey()

    /**
     * @group accessors
     */
    public function testGetPrimaryKey()
    {
        $key = new Crypt_GPG_Key();

        $firstSubKey = new Crypt_GPG_SubKey(array(
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $key->addSubKey($firstSubKey);

        $secondSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '9F93F9116728EF12',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'C9C65B3BBF040E40D0EA27B79F93F9116728EF12',
            'length'      => 2048,
            'creation'    => 1221785821,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $key->addSubKey($secondSubKey);

        $primaryKey = $key->getPrimaryKey();

        $this->assertEquals($firstSubKey, $primaryKey,
            'Failed to assert the primary key is the same as the first added ' .
            'sub-key.');
    }

    // }}}
    // {{{ testCanSign_none()

    /**
     * @group accessors
     */
    public function testCanSign_none()
    {
        $key = new Crypt_GPG_Key();

        $subKey = new Crypt_GPG_SubKey(array('canSign' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canSign' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canSign' => false));
        $key->addSubKey($subKey);

        $this->assertFalse($key->canSign());
    }

    // }}}
    // {{{ testCanSign_one()

    /**
     * @group accessors
     */
    public function testCanSign_one()
    {
        $key = new Crypt_GPG_Key();

        $subKey = new Crypt_GPG_SubKey(array('canSign' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canSign' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canSign' => true));
        $key->addSubKey($subKey);

        $this->assertTrue($key->canSign());
    }

    // }}}
    // {{{ testCanSign_all()

    /**
     * @group accessors
     */
    public function testCanSign_all()
    {
        $key = new Crypt_GPG_Key();

        $subKey = new Crypt_GPG_SubKey(array('canSign' => true));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canSign' => true));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canSign' => true));
        $key->addSubKey($subKey);

        $this->assertTrue($key->canSign());
    }

    // }}}
    // {{{ testCanEncrypt_none()

    /**
     * @group accessors
     */
    public function testCanEncrypt_none()
    {
        $key = new Crypt_GPG_Key();

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => false));
        $key->addSubKey($subKey);

        $this->assertFalse($key->canEncrypt());
    }

    // }}}
    // {{{ testCanEncrypt_one()

    /**
     * @group accessors
     */
    public function testCanEncrypt_one()
    {
        $key = new Crypt_GPG_Key();

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => false));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => true));
        $key->addSubKey($subKey);

        $this->assertTrue($key->canEncrypt());
    }

    // }}}
    // {{{ testCanEncrypt_all()

    /**
     * @group accessors
     */
    public function testCanEncrypt_all()
    {
        $key = new Crypt_GPG_Key();

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => true));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => true));
        $key->addSubKey($subKey);

        $subKey = new Crypt_GPG_SubKey(array('canEncrypt' => true));
        $key->addSubKey($subKey);

        $this->assertTrue($key->canEncrypt());
    }

    // }}}
    // {{{ test__toString()

    /**
     * @group accessors
     */
    public function test__toString()
    {
        $key = new Crypt_GPG_Key();

        $firstSubKey = new Crypt_GPG_SubKey(array(
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $this->assertSame((string) $key, '');

        $key->addSubKey($firstSubKey);

        $this->assertSame((string) $key, $firstSubKey->getId());
    }

    // }}}

    // mutators
    // {{{ testAddSubKey()

    /**
     * @group mutators
     */
    public function testAddSubKey()
    {
        $key = new Crypt_GPG_Key();

        $subKeys = $key->getSubKeys();
        $this->assertTrue(is_array($subKeys),
            'Failed to assert returned sub-keys is an array.');

        $this->assertEquals(0, count($subKeys),
            'Failed to assert there are no sub-keys.');

        // add first sub-key
        $firstSubKey = new Crypt_GPG_SubKey(array(
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $key->addSubKey($firstSubKey);

        $subKeys = $key->getSubKeys();
        $this->assertTrue(is_array($subKeys),
            'Failed to assert returned sub-keys is an array.');

        $this->assertEquals(1, count($subKeys),
            'Failed to assert number of returned sub-keys is the same as ' .
            'the number of sub-keys added.');

        $this->assertContainsOnly('Crypt_GPG_SubKey', $subKeys, false,
            'Failed to assert all returned sub-keys are Crypt_GPG_SubKey ' .
            'objects.');

        $this->assertArrayHasKey(0, $subKeys);
        $this->assertEquals($subKeys[0], $firstSubKey,
            'Failed to assert the first sub-key is the same as the first ' .
            'added sub-key.');

        // add second sub-key
        $secondSubKey = new Crypt_GPG_SubKey(array(
            'id'          => '9F93F9116728EF12',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'C9C65B3BBF040E40D0EA27B79F93F9116728EF12',
            'length'      => 2048,
            'creation'    => 1221785821,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true
        ));

        $key->addSubKey($secondSubKey);

        $subKeys = $key->getSubKeys();
        $this->assertTrue(is_array($subKeys),
            'Failed to assert returned sub-keys is an array.');

        $this->assertEquals(2, count($subKeys),
            'Failed to assert number of returned sub-keys is the same as ' .
            'the number of sub-keys added.');

        $this->assertContainsOnly('Crypt_GPG_SubKey', $subKeys, false,
            'Failed to assert all returned sub-keys are Crypt_GPG_SubKey ' .
            'objects.');

        $this->assertArrayHasKey(0, $subKeys);
        $this->assertEquals($subKeys[0], $firstSubKey,
            'Failed to assert the first sub-key is the same as the first ' .
            'added sub-key.');

        $this->assertArrayHasKey(1, $subKeys);
        $this->assertEquals($subKeys[1], $secondSubKey,
            'Failed to assert the second sub-key is the same as the second ' .
            'added sub-key.');
    }

    // }}}
    // {{{ testAddUserId()

    /**
     * @group mutators
     */
    public function testAddUserId()
    {
        $key = new Crypt_GPG_Key();

        $userIds = $key->getUserIds();
        $this->assertTrue(is_array($userIds),
            'Failed to assert returned user ids is an array.');

        $this->assertEquals(0, count($userIds),
            'Failed to assert there are no user ids.');

        // add first user id
        $firstUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com'
        ));

        $key->addUserId($firstUserId);

        $userIds = $key->getUserIds();
        $this->assertTrue(is_array($userIds),
            'Failed to assert returned user ids is an array.');

        $this->assertEquals(1, count($userIds),
            'Failed to assert number of returned user ids is the same as ' .
            'the number of user ids added.');

        $this->assertContainsOnly('Crypt_GPG_UserId', $userIds, false,
            'Failed to assert all returned user ids are Crypt_GPG_UserId ' .
            'objects.');

        $this->assertArrayHasKey(0, $userIds);
        $this->assertEquals($userIds[0], $firstUserId,
            'Failed to assert the first user id is the same as the first ' .
            'added user id.');

        // add second user id
        $secondUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Bob',
            'comment' => 'receiving',
            'email'   => 'bob@example.com'
        ));

        $key->addUserId($secondUserId);

        $userIds = $key->getUserIds();
        $this->assertTrue(is_array($userIds),
            'Failed to assert returned user ids is an array.');

        $this->assertEquals(2, count($userIds),
            'Failed to assert number of returned user ids is the same as ' .
            'the number of user ids added.');

        $this->assertContainsOnly('Crypt_GPG_UserId', $userIds, false,
            'Failed to assert all returned user ids are Crypt_GPG_UserId ' .
            'objects.');

        $this->assertArrayHasKey(0, $userIds);
        $this->assertEquals($userIds[0], $firstUserId,
            'Failed to assert the first user id is the same as the first ' .
            'added user id.');

        $this->assertArrayHasKey(1, $userIds);
        $this->assertEquals($userIds[1], $secondUserId,
            'Failed to assert the second user id is the same as the second ' .
            'added user id.');
    }

    // }}}

    // fluent interface
    // {{{ testFluentInterface

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $key = new Crypt_GPG_Key();

        // add first sub-key
        $firstSubKey = new Crypt_GPG_SubKey(array(
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => Crypt_GPG_SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true
        ));

        $returnedKey = $key->addSubKey($firstSubKey);

        $this->assertEquals(
            $key,
            $returnedKey,
            'Failed asserting fluent interface works for addSubKey() method.'
        );

        $firstUserId = new Crypt_GPG_UserId(array(
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com'
        ));

        $returnedKey = $key->addUserId($firstUserId);

        $this->assertEquals(
            $key,
            $returnedKey,
            'Failed asserting fluent interface works for addUserId() method.'
        );
    }

    // }}}
}

?>
