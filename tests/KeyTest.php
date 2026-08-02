<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG\Key;
use Crypt\GPG\SubKey;
use Crypt\GPG\UserId;

/**
 * Key class tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2010 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class KeyTest extends TestCase
{
    /**
     * @group accessors
     */
    public function testGetSubKeys()
    {
        $key = new Key();

        $firstSubKey = new SubKey([
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $key->addSubKey($firstSubKey);

        $secondSubKey = new SubKey([
            'id'          => '9F93F9116728EF12',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'C9C65B3BBF040E40D0EA27B79F93F9116728EF12',
            'length'      => 2048,
            'creation'    => 1221785821,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $key->addSubKey($secondSubKey);

        $subKeys = $key->getSubKeys();

        $this->assertEquals(
            2,
            count($subKeys),
            'Failed to assert number of returned sub-keys is the same as '
            . 'the number of sub-keys added.'
        );

        $this->assertContainsOnly(
            SubKey::class,
            $subKeys,
            false,
            'Failed to assert all returned sub-keys are Crypt_GPG_SubKey '
            . 'objects.'
        );

        $this->assertArrayHasKey(0, $subKeys);
        $this->assertEquals(
            $subKeys[0],
            $firstSubKey,
            'Failed to assert the first sub-key is the same as the first '
            . 'added sub-key.'
        );

        $this->assertArrayHasKey(1, $subKeys);
        $this->assertEquals(
            $subKeys[1],
            $secondSubKey,
            'Failed to assert the second sub-key is the same as the second '
            . 'added sub-key.'
        );
    }

    /**
     * @group accessors
     */
    public function testGetUserIds()
    {
        $key = new Key();

        $firstUserId = new UserId([
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com',
        ]);

        $key->addUserId($firstUserId);

        $secondUserId = new UserId([
            'name'    => 'Bob',
            'comment' => 'receiving',
            'email'   => 'bob@example.com',
        ]);

        $key->addUserId($secondUserId);

        $userIds = $key->getUserIds();

        $this->assertCount(
            2,
            $userIds,
            'Failed to assert number of returned user ids is the same as '
            . 'the number of user ids added.'
        );

        $this->assertContainsOnly(
            UserId::class,
            $userIds,
            false,
            'Failed to assert all returned user ids are UserId '
            . 'objects.'
        );

        $this->assertArrayHasKey(0, $userIds);
        $this->assertEquals(
            $userIds[0],
            $firstUserId,
            'Failed to assert the first user id is the same as the first '
            . 'added user id.'
        );

        $this->assertArrayHasKey(1, $userIds);
        $this->assertEquals(
            $userIds[1],
            $secondUserId,
            'Failed to assert the second user id is the same as the second '
            . 'added user id.'
        );
    }

    /**
     * @group accessors
     */
    public function testGetPrimaryKey()
    {
        $key = new Key();

        $firstSubKey = new SubKey([
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $key->addSubKey($firstSubKey);

        $secondSubKey = new SubKey([
            'id'          => '9F93F9116728EF12',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'C9C65B3BBF040E40D0EA27B79F93F9116728EF12',
            'length'      => 2048,
            'creation'    => 1221785821,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $key->addSubKey($secondSubKey);

        $primaryKey = $key->getPrimaryKey();

        $this->assertEquals(
            $firstSubKey,
            $primaryKey,
            'Failed to assert the primary key is the same as the first added '
            . 'sub-key.'
        );
    }

    /**
     * @group accessors
     */
    public function testCanSign_none()
    {
        $key = new Key();

        $subKey = new SubKey(['canSign' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canSign' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canSign' => false]);
        $key->addSubKey($subKey);

        $this->assertFalse($key->canSign());
    }

    /**
     * @group accessors
     */
    public function testCanSign_one()
    {
        $key = new Key();

        $subKey = new SubKey(['canSign' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canSign' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canSign' => true]);
        $key->addSubKey($subKey);

        $this->assertTrue($key->canSign());
    }

    /**
     * @group accessors
     */
    public function testCanSign_all()
    {
        $key = new Key();

        $subKey = new SubKey(['canSign' => true]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canSign' => true]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canSign' => true]);
        $key->addSubKey($subKey);

        $this->assertTrue($key->canSign());
    }

    /**
     * @group accessors
     */
    public function testCanEncrypt_none()
    {
        $key = new Key();

        $subKey = new SubKey(['canEncrypt' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canEncrypt' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canEncrypt' => false]);
        $key->addSubKey($subKey);

        $this->assertFalse($key->canEncrypt());
    }

    /**
     * @group accessors
     */
    public function testCanEncrypt_one()
    {
        $key = new Key();

        $subKey = new SubKey(['canEncrypt' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canEncrypt' => false]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canEncrypt' => true]);
        $key->addSubKey($subKey);

        $this->assertTrue($key->canEncrypt());
    }

    /**
     * @group accessors
     */
    public function testCanEncrypt_all()
    {
        $key = new Key();

        $subKey = new SubKey(['canEncrypt' => true]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canEncrypt' => true]);
        $key->addSubKey($subKey);

        $subKey = new SubKey(['canEncrypt' => true]);
        $key->addSubKey($subKey);

        $this->assertTrue($key->canEncrypt());
    }

    /**
     * @group accessors
     */
    public function test__toString()
    {
        $key = new Key();

        $firstSubKey = new SubKey([
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $this->assertSame((string) $key, '');

        $key->addSubKey($firstSubKey);

        $this->assertSame((string) $key, $firstSubKey->getId());
    }

    /**
     * @group mutators
     */
    public function testAddSubKey()
    {
        $key = new Key();

        $subKeys = $key->getSubKeys();

        $this->assertCount(
            0,
            $subKeys,
            'Failed to assert there are no sub-keys.'
        );

        // add first sub-key
        $firstSubKey = new SubKey([
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $key->addSubKey($firstSubKey);

        $subKeys = $key->getSubKeys();

        $this->assertCount(
            1,
            $subKeys,
            'Failed to assert number of returned sub-keys is the same as '
            . 'the number of sub-keys added.'
        );

        $this->assertContainsOnly(
            SubKey::class,
            $subKeys,
            false,
            'Failed to assert all returned sub-keys are SubKey '
            . 'objects.'
        );

        $this->assertArrayHasKey(0, $subKeys);
        $this->assertEquals(
            $subKeys[0],
            $firstSubKey,
            'Failed to assert the first sub-key is the same as the first '
            . 'added sub-key.'
        );

        // add second sub-key
        $secondSubKey = new SubKey([
            'id'          => '9F93F9116728EF12',
            'algorithm'   => SubKey::ALGORITHM_ELGAMAL_ENC,
            'fingerprint' => 'C9C65B3BBF040E40D0EA27B79F93F9116728EF12',
            'length'      => 2048,
            'creation'    => 1221785821,
            'expiration'  => 0,
            'canSign'     => false,
            'canEncrypt'  => true,
            'hasPrivate'  => true,
        ]);

        $key->addSubKey($secondSubKey);

        $subKeys = $key->getSubKeys();

        $this->assertCount(
            2,
            $subKeys,
            'Failed to assert number of returned sub-keys is the same as '
            . 'the number of sub-keys added.'
        );

        $this->assertContainsOnly(
            SubKey::class,
            $subKeys,
            false,
            'Failed to assert all returned sub-keys are SubKey objects.'
        );

        $this->assertArrayHasKey(0, $subKeys);
        $this->assertEquals(
            $subKeys[0],
            $firstSubKey,
            'Failed to assert the first sub-key is the same as the first '
            . 'added sub-key.'
        );

        $this->assertArrayHasKey(1, $subKeys);
        $this->assertEquals(
            $subKeys[1],
            $secondSubKey,
            'Failed to assert the second sub-key is the same as the second '
            . 'added sub-key.'
        );
    }

    /**
     * @group mutators
     */
    public function testAddUserId()
    {
        $key = new Key();

        $userIds = $key->getUserIds();

        $this->assertCount(0, $userIds, 'Failed to assert there are no user ids.');

        // add first user id
        $firstUserId = new UserId([
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com',
        ]);

        $key->addUserId($firstUserId);

        $userIds = $key->getUserIds();

        $this->assertCount(
            1,
            $userIds,
            'Failed to assert number of returned user ids is the same as '
            . 'the number of user ids added.'
        );

        $this->assertContainsOnly(
            UserId::class,
            $userIds,
            false,
            'Failed to assert all returned user ids are UserId objects.'
        );

        $this->assertArrayHasKey(0, $userIds);
        $this->assertEquals(
            $userIds[0],
            $firstUserId,
            'Failed to assert the first user id is the same as the first '
            . 'added user id.'
        );

        // add second user id
        $secondUserId = new UserId([
            'name'    => 'Bob',
            'comment' => 'receiving',
            'email'   => 'bob@example.com',
        ]);

        $key->addUserId($secondUserId);

        $userIds = $key->getUserIds();

        $this->assertCount(
            2,
            $userIds,
            'Failed to assert number of returned user ids is the same as '
            . 'the number of user ids added.'
        );

        $this->assertContainsOnly(
            UserId::class,
            $userIds,
            false,
            'Failed to assert all returned user ids are UserId '
            . 'objects.'
        );

        $this->assertArrayHasKey(0, $userIds);
        $this->assertEquals(
            $userIds[0],
            $firstUserId,
            'Failed to assert the first user id is the same as the first '
            . 'added user id.'
        );

        $this->assertArrayHasKey(1, $userIds);
        $this->assertEquals(
            $userIds[1],
            $secondUserId,
            'Failed to assert the second user id is the same as the second '
            . 'added user id.'
        );
    }

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $key = new Key();

        // add first sub-key
        $firstSubKey = new SubKey([
            'id'          => 'C097D9EC94C06363',
            'algorithm'   => SubKey::ALGORITHM_DSA,
            'fingerprint' => '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'length'      => 1024,
            'creation'    => 1221785805,
            'expiration'  => 0,
            'canSign'     => true,
            'canEncrypt'  => false,
            'hasPrivate'  => true,
        ]);

        $returnedKey = $key->addSubKey($firstSubKey);

        $this->assertEquals(
            $key,
            $returnedKey,
            'Failed asserting fluent interface works for addSubKey() method.'
        );

        $firstUserId = new UserId([
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com',
        ]);

        $returnedKey = $key->addUserId($firstUserId);

        $this->assertEquals(
            $key,
            $returnedKey,
            'Failed asserting fluent interface works for addUserId() method.'
        );
    }
}
