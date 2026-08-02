<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Tests;

use Crypt\GPG;
use Crypt\GPG\SignatureCreationInfo;

/**
 * Test the signature creation information class
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class SignatureCreationInfoTest extends TestCase
{
    public function testValidSigCreatedLine()
    {
        $sci = new SignatureCreationInfo(
            'SIG_CREATED D 17 2 00 1440922957 8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertTrue($sci->isValid());
        $this->assertEquals(GPG::SIGN_MODE_DETACHED, $sci->getMode());
        $this->assertEquals(1440922957, $sci->getTimestamp());
        $this->assertEquals(17, $sci->getPkAlgorithm());
        $this->assertEquals(2, $sci->getHashAlgorithm());
        $this->assertEquals('sha1', $sci->getHashAlgorithmName());
        $this->assertEquals(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363',
            $sci->getKeyFingerprint()
        );
    }

    public function testInvalidSigCreatedLine()
    {
        $sci = new SignatureCreationInfo('foo bar');
        $this->assertNull($sci->getMode());
        $this->assertFalse($sci->isValid());
    }
}
