<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * KeyEditor class test cases for the Crypt_GPG package.
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
 * @author    Aleksander Machniak <machniak@apheleia-it.ch>
 * @copyright Apheleia IT AG <contact@apheleia-it.ch>
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

require_once 'TestCase.php';
require_once 'Crypt/GPG/KeyEditor.php';

/**
 * KeyEditor class tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Aleksander Machniak <machniak@apheleia-it.ch>
 * @copyright Apheleia IT AG <contact@apheleia-it.ch>
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class KeyEditorTest extends Crypt_GPG_TestCase
{
    /**
     * Test unknown key
     */
    public function testUnknownKey()
    {
        $this->expectException('Crypt_GPG_OpenSubprocessException');

        $keyEditor = $this->gpg->getKeyEditor();
        $keyEditor->edit('unknown@example.com', 'test');
    }

    /**
     * Test `adduid` command
     */
    public function testAddUserId()
    {
        $keyEditor = $this->gpg->getKeyEditor();

        // Test successful user addition
        $user = new Crypt_GPG_UserId([
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com'
        ]);

        $keyEditor->edit('first-keypair@example.com', 'test1')
            ->addUserId($user)
            ->save();

        $keys = $this->gpg->getKeys('first-keypair@example.com');

        $userIds = $keys[0]->getUserIds();
        $this->assertCount(2, $userIds);

        $userIds = array_filter($userIds, function ($id) use ($user) { return $id->getName() == $user->getName(); });
        $this->assertCount(1, $userIds);

        $userId = $userIds[key($userIds)];
        $this->assertSame($user->getEmail(), $userId->getEmail());
        $this->assertSame($user->getComment(), $userId->getComment());

        // Test that `quit` does not save.
        $user = new Crypt_GPG_UserId([
            'name'    => 'Alice2',
            'comment' => '',
            'email'   => 'alice2@example.com'
        ]);

        $keyEditor->edit('first-keypair@example.com', 'test1')
            ->addUserId($user)
            ->quit();

        $keys = $this->gpg->getKeys('first-keypair@example.com');

        $userIds = $keys[0]->getUserIds();
        $this->assertCount(2, $userIds);

        $userIds = array_filter($userIds, function ($id) use ($user) { return $id->getName() == $user->getName(); });
        $this->assertCount(0, $userIds);

        // Test editing a key that has no secret key
        $this->expectException('Crypt_GPG_Exception');
        $keyEditor->edit('public-only@example.com', 'test')->addUserId($user)->save();

        // Test invalid password
        $this->expectException('Crypt_GPG_BadPassphraseException');
        $keyEditor->edit('second-keypair@example.com', 'wrong')->addUserId($user)->save();
    }

    /**
     * Test `deluid` command
     */
    public function testDeleteUserId()
    {
        $keyEditor = $this->gpg->getKeyEditor();

        // First add some users to the key
        $user1 = new Crypt_GPG_UserId([
            'name'    => 'Alice',
            'comment' => 'shipping',
            'email'   => 'alice@example.com'
        ]);

        $user2 = new Crypt_GPG_UserId([
            'name'    => 'John',
            'comment' => '',
            'email'   => 'john@example.com'
        ]);

        $user3 = new Crypt_GPG_UserId([
            'name'    => '',
            'comment' => '',
            'email'   => 'john@example.com'
        ]);

        $keyEditor->edit('second-keypair@example.com', 'test2')
            ->addUserId($user1)
            ->addUserId($user2)
            ->addUserId($user3)
            ->save();

        // Test deleting user with name, comment and email
        $keyEditor->edit('second-keypair@example.com', 'test2')->deleteUserId($user1)->save();

        $keys = $this->gpg->getKeys('second-keypair@example.com');
        $userIds = $keys[0]->getUserIds();
        $this->assertCount(3, $userIds);
        $userIds = array_filter($userIds, function ($id) use ($user1) { return $id->getEmail() != $user1->getEmail(); });
        $this->assertCount(3, $userIds);

        // Test deleting users with no name or no comment
        $keyEditor->edit('second-keypair@example.com', 'test2')
            ->deleteUserId($user2)
            ->deleteUserId($user3)
            ->save();

        $keys = $this->gpg->getKeys('second-keypair@example.com');
        $userIds = $keys[0]->getUserIds();
        $this->assertCount(1, $userIds);
        $userIds = array_filter($userIds, function ($id) use ($user1) { return $id->getEmail() != $user1->getEmail(); });
        $this->assertCount(1, $userIds);

        // Test deleting the last user
        $user = new Crypt_GPG_UserId('Second Keypair Test Key (do not encrypt important data with this key) <second-keypair@example.com>');
        $this->expectException('Crypt_GPG_Exception');
        $keyEditor->edit('second-keypair@example.com', 'test2')->deleteUserId($user)->save();
    }

    /**
     * Test `deluid` command with a non-existing user
     */
    public function testDeleteUserIdUnknown()
    {
        $keyEditor = $this->gpg->getKeyEditor();
        $user = new Crypt_GPG_UserId('<unknown-keypair@example.com>');
        $this->expectException('Crypt_GPG_Exception');
        $keyEditor->edit('second-keypair@example.com', 'test2')->deleteUserId($user)->save();
    }

    /**
     * Test `expire` command
     */
    public function testExpire()
    {
        $keyEditor = $this->gpg->getKeyEditor();

        // Test setting an expiration date (one year from today)
        $keyEditor->edit('second-keypair@example.com', 'test2')->expire('1y')->save();

        $keys = $this->gpg->getKeys('second-keypair@example.com');
        $primary = $keys[0]->getPrimaryKey();
        $this->assertSame((date('Y') + 1) . date('-m-d'), $primary->getExpirationDateTime()->format('Y-m-d'));

        // Test unsetting an expiration date
        $keyEditor->edit('second-keypair@example.com', 'test2')->expire(0)->save();

        $keys = $this->gpg->getKeys('second-keypair@example.com');
        $primary = $keys[0]->getPrimaryKey();
        $this->assertNull($primary->getExpirationDateTime());

        // Test invalid period
        $this->expectException('Crypt_GPG_Exception');
        $keyEditor->edit('second-keypair@example.com', 'test2')->expire('-1')->save();
    }

    /**
     * Test `passwd` command
     */
    public function testPasswd()
    {
        $keyEditor = $this->gpg->getKeyEditor();
        $keyEditor->edit('first-keypair@example.com', 'test1')->passwd('new pass')->save();

        // Assert the new password in fact works
        $keyEditor->edit('first-keypair@example.com', 'new pass')
            ->addUserId($user = new Crypt_GPG_UserId('alice@example.com'))
            ->save();

        $this->assertTrue(true);
    }

    /**
     * Test `revuid` command
     */
    public function testRevokeUserId()
    {
        $keyEditor = $this->gpg->getKeyEditor();

        // First add some users to the key
        $user1 = (new Crypt_GPG_UserId())->setEmail('alice@example.com');

        // Add the user to revoke
        $keyEditor->edit('second-keypair@example.com', 'test2')->addUserId($user1)->save();

        // Test deleting user with name, comment and email
        $keyEditor->edit('second-keypair@example.com', 'test2')->revokeUserId($user1)->save();

        $keys = $this->gpg->getKeys('second-keypair@example.com');
        $userIds = $keys[0]->getUserIds();
        $this->assertCount(2, $userIds);
        $userIds = array_values(array_filter($userIds, function ($id) use ($user1) { return $id->getEmail() == $user1->getEmail(); }));
        $this->assertCount(1, $userIds);
        $this->assertTrue($userIds[0]->isRevoked());

        // Test revoking the last user
        $user = new Crypt_GPG_UserId('Second Keypair Test Key (do not encrypt important data with this key) <second-keypair@example.com>');
        $this->expectException('Crypt_GPG_Exception');
        $keyEditor->edit('second-keypair@example.com', 'test2')->revokeUserId($user)->save();
    }

    /**
     * Test `revuid` command with a non-existing user
     */
    public function testRevokeUserIdUnknown()
    {
        $keyEditor = $this->gpg->getKeyEditor();
        $user = new Crypt_GPG_UserId('<unknown-keypair@example.com>');
        $this->expectException('Crypt_GPG_Exception');
        $keyEditor->edit('second-keypair@example.com', 'test2')->revokeUserId($user)->save();
    }

    /**
     * Test `sign` command
     */
    public function testSign()
    {
        $keys = $this->gpg->getKeys('public-only@example.com');

        $keyEditor = $this->gpg->getKeyEditor();

        // Sign the key using second-keypair@example.com key
        $opts = ['--allow-weak-key-signatures', '--local-user=second-keypair@example.com'];
        $keyEditor->edit('public-only@example.com', 'test2', $opts)->sign()->save();

        $this->assertSame(
            ['public-only@example.com', 'second-keypair@example.com'],
            $this->_getKeySignaturesEmails('public-only@example.com')
        );

        // Sign the key using first-keypair@example.com key
        $opts = ['--allow-weak-key-signatures', '--local-user=first-keypair@example.com'];
        $keyEditor->edit('public-only@example.com', 'test1', $opts)->sign()->save();

        $this->assertSame(
            ['first-keypair@example.com', 'public-only@example.com', 'second-keypair@example.com'],
            $this->_getKeySignaturesEmails('public-only@example.com')
        );
    }

    /**
     * Get emails for all signatures on a public key
     */
    private function _getKeySignaturesEmails($keyId)
    {
        $emails = [];

        foreach ($this->gpg->setEngineOptions(['list-public-keys' => '--with-sig-list'])->getKeys($keyId) as $key) {
            foreach ($key->getUserIds() as $user) {
                foreach ($user->getSignatures() as $sig) {
                    $user = $sig->getUserId();
                    $emails[] = $user->getEmail();
                }
            }
        }

        sort($emails);

        return $emails;
    }
}
