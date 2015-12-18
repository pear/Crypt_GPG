<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Unit tests for Crypt_GPG
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
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

//require_once 'Crypt/GPG/SignatureCreationInfo.php';

/**
 * Test the signature creation information class
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class SignatureCreationInfoTest extends Crypt_GPG_TestCase
{

    public function testValidSigCreatedLine()
    {
        $sci = new Crypt_GPG_SignatureCreationInfo(
            'SIG_CREATED D 17 2 00 1440922957 8D2299D9C5C211128B32BBB0C097D9EC94C06363'
        );
        $this->assertTrue($sci->isValid());
        $this->assertEquals(Crypt_GPG::SIGN_MODE_DETACHED, $sci->getMode());
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
        $sci = new Crypt_GPG_SignatureCreationInfo('foo bar');
        $this->assertNull($sci->getMode());
        $this->assertFalse($sci->isValid());
    }
}
?>
