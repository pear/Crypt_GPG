<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG;
use Crypt\GPG\Engine;
use Crypt\GPG\Exceptions;

/**
 * General tests for Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008-2013 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class GeneralTest extends TestCase
{
    public function testPublicKeyringFileException()
    {
        $this->expectException(Exceptions\FileException::class);

        $publicKeyringFile = $this->getTempFilename('pubring.gpg');
        new GPG(['publicKeyring' => $publicKeyringFile]);
    }

    public function testPrivateKeyringFileException()
    {
        $this->expectException(Exceptions\FileException::class);

        $privateKeyringFile = $this->getTempFilename('secring.gpg');
        new GPG(['privateKeyring' => $privateKeyringFile]);
    }

    public function testTrustDatabaseFileException()
    {
        $this->expectException(Exceptions\FileException::class);

        $trustDbFile = $this->getTempFilename('secring.gpg');
        new GPG(['trustDb' => $trustDbFile]);
    }

    public function testHomedirFileException_NoCreate()
    {
        $this->expectException(Exceptions\FileException::class);
        $this->expectExceptionMessage('cannot be created');

        if (posix_getuid() === 0) {
            $this->markTestSkipped('Root can write to any homedir.');
        }

        $nonCreatableDirectory = '//.gnupg';
        new GPG(['homedir' => $nonCreatableDirectory]);
    }

    public function testHomedirFileException_NoExecute()
    {
        $this->expectException(Exceptions\FileException::class);
        $this->expectExceptionMessage('is not enterable');

        if (posix_getuid() === 0) {
            $this->markTestSkipped('Root can do what it wants to any homedir.');
        }

        $nonExecutableDirectory = $this->getTempFilename('home-no-execute');
        mkdir($nonExecutableDirectory);
        chmod($nonExecutableDirectory, 0o600); // rw- --- ---

        new GPG(['homedir' => $nonExecutableDirectory]);
    }

    public function testHomedirFileException_NoWrite()
    {
        $this->expectException(Exceptions\FileException::class);
        $this->expectExceptionMessage('is not writable');

        if (posix_getuid() === 0) {
            $this->markTestSkipped('Root can write to any homedir.');
        }

        $nonWriteableDirectory = $this->getTempFilename('home-no-write');
        mkdir($nonWriteableDirectory);
        chmod($nonWriteableDirectory, 0o500); // r-x --- ---

        new GPG(['homedir' => $nonWriteableDirectory]);
    }

    public function testBinaryPEARException()
    {
        $this->expectException(Exceptions\Exception::class);

        new GPG(['binary' => './non-existent-binary']);
    }

    public function testGPGBinaryPEARException()
    {
        $this->expectException(Exceptions\Exception::class);

        new GPG(['gpgBinary' => './non-existent-binary']);
    }

    public function testSetEngine()
    {
        $engine = new Engine($this->getOptions());
        $gpg = new GPG();
        $gpg->setEngine($engine);

        $this->assertSame($this->getPropertyValue(GPG::class, $gpg, 'engine'), $engine);
    }

    /**
     * @group fluent
     */
    public function testFluentInterface()
    {
        $returnedGpg = $this->gpg->setEngine(new Engine($this->getOptions()));
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for setEngine() method.'
        );

        $returnedGpg = $this->gpg->addDecryptKey(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'test1'
        );
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for addDecryptKey() '
            . 'method.'
        );

        $returnedGpg = $this->gpg->addEncryptKey(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for addEncryptKey() '
            . 'method.'
        );

        $returnedGpg = $this->gpg->addSignKey(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            'test1'
        );
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for addSignKey() '
            . 'method.'
        );

        $returnedGpg = $this->gpg->clearDecryptKeys();
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for clearDecryptKeys() '
            . 'method.'
        );

        $returnedGpg = $this->gpg->clearEncryptKeys();
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for clearEncryptKeys() '
            . 'method.'
        );

        $returnedGpg = $this->gpg->clearSignKeys();
        $this->assertEquals(
            $this->gpg,
            $returnedGpg,
            'Failed asserting fluent interface works for clearSignKeys() '
            . 'method.'
        );
    }
}
