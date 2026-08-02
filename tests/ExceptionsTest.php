<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG\Exceptions;

/**
 * Exception classes tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2011 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class ExceptionsTest extends TestCase
{
    /**
     * @group exception
     */
    public function testException()
    {
        $this->expectException(Exceptions\Exception::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\Exception('test exception');
    }

    /**
     * @group file-exception
     */
    public function testFileException()
    {
        $this->expectException(Exceptions\FileException::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\FileException('test exception');
    }

    /**
     * @group file-exception
     */
    public function testFileException_getFilename()
    {
        $e = new Exceptions\FileException('test exception', 0, 'test-filename.php');

        $this->assertEquals('test-filename.php', $e->getFilename());
    }

    /**
     * @group open-subprocess-exception
     */
    public function testOpenSubprocessException()
    {
        $this->expectException(Exceptions\OpenSubprocessException::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\OpenSubprocessException('test exception');
    }

    /**
     * @group open-subprocess-exception
     */
    public function testOpenSubprocessException_getCommand()
    {
        $e = new Exceptions\OpenSubprocessException('test exception', 0, 'gpg --verify');

        $this->assertEquals('gpg --verify', $e->getCommand());
    }

    /**
     * @group invalid-operation-exception
     */
    public function testInvalidOperationException()
    {
        $this->expectException(Exceptions\InvalidOperationException::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\InvalidOperationException('test exception');
    }

    /**
     * @group invalid-operation-exception
     */
    public function testInvalidOperationException_getOperation()
    {
        $e = new Exceptions\InvalidOperationException('test exception', 0, '--verify');

        $this->assertEquals('--verify', $e->getOperation());
    }

    /**
     * @group key-not-found-exception
     */
    public function testKeyNotFoundException()
    {
        $this->expectException(Exceptions\KeyNotFoundException::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\KeyNotFoundException('test exception');
    }

    /**
     * @group key-not-found-exception
     */
    public function testKeyNotFoundException_getKeyId()
    {
        $e = new Exceptions\KeyNotFoundException('test exception', 0, '9F93F9116728EF12');

        $this->assertEquals('9F93F9116728EF12', $e->getKeyId());
    }

    /**
     * @group no-data-exception
     */
    public function testNoDataException()
    {
        $this->expectException(Exceptions\NoDataException::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\NoDataException('test exception');
    }

    /**
     * @group bad-passphrase-exception
     */
    public function testBadPassphraseException()
    {
        $this->expectException(Exceptions\BadPassphraseException::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\BadPassphraseException('test exception');
    }

    /**
     * @group bad-passphrase-exception
     */
    public function testBadPassphraseException_getBadPassphrases()
    {
        $e = new Exceptions\BadPassphraseException(
            'test exception',
            0,
            ['C097D9EC94C06363', '9F93F9116728EF12']
        );

        $keyIds = $e->getBadPassphrases();

        $this->assertContains('C097D9EC94C06363', $keyIds);
        $this->assertContains('9F93F9116728EF12', $keyIds);
    }

    /**
     * @group bad-passphrase-exception
     */
    public function testBadPassphraseException_getMissingPassphrase()
    {
        $e = new Exceptions\BadPassphraseException(
            'test exception',
            0,
            [],
            ['C097D9EC94C06363', '9F93F9116728EF12']
        );

        $keyIds = $e->getMissingPassphrases();

        $this->assertContains('C097D9EC94C06363', $keyIds);
        $this->assertContains('9F93F9116728EF12', $keyIds);
    }

    /**
     * @group delete-private-key-exception
     */
    public function testDeletePrivateKeyException()
    {
        $this->expectException(Exceptions\DeletePrivateKeyException::class);
        $this->expectExceptionMessage('test exception');

        throw new Exceptions\DeletePrivateKeyException('test exception');
    }

    /**
     * @group delete-private-key-exception
     */
    public function testDeletePrivateKeyException_getKeyId()
    {
        $e = new Exceptions\DeletePrivateKeyException(
            'test exception',
            0,
            '9F93F9116728EF12'
        );

        $this->assertEquals('9F93F9116728EF12', $e->getKeyId());
    }
}
