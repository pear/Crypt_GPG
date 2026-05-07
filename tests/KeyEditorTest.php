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
require_once 'Crypt/GPG/Key.php';
require_once 'Crypt/GPG/UserId.php';
require_once 'Crypt/GPG/SubKey.php';
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

        // Test invalid password
        $this->expectException('Crypt_GPG_BadPassphraseException');
        $keyEditor->edit('second-keypair@example.com', 'wrong')
            ->addUserId($user)
            ->save();
    }

    /**
     * Test `deluid` command
     */
    public function testDeleteUserId()
    {
        $this->markTestIncomplete();
    }
}
