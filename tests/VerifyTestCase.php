<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Verify tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit VerifyTestCase
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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

/**
 * Tests verification abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class VerifyTestCase extends TestCase
{
    // {{{ testVerifyNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group verify
     */
    public function testVerifyNoDataException()
    {
        $signedData = 'Invalid OpenPGP data.';
        $signature = $this->gpg->verify($signedData);
    }

    // }}}
    // {{{ testVerifyNormalSignedData()

    /**
     * @group verify
     */
    public function testVerifyNormalSignedData()
    {
        // {{{ expected signature
        $expectedSignature = new Crypt_GPG_Signature();
        $expectedSignature->setId('vQ2mozoe+N5TQhaFsRAJmNHhsBY');
        $expectedSignature->setKeyFingerprint(
            '5A58436F752BC80B3E992C1D300579D099645239');

        $expectedSignature->setCreationDate(1200674360);
        $expectedSignature->setExpirationDate(0);
        $expectedSignature->setIsValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Public and Private Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('public-and-private@example.com');
        $expectedSignature->setUserId($userId);
        // }}}
        // {{{ normal signed data
        $normalSignedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

owGbwMvMwCRowFp5YWZKkCXjacUkBvcJ1/Q8UnNy8nUUHHMyk1MVFdzz81OSKlN1
FJzykxQ77JlZQWosYJoEmb5fY5ins3He0itLAmPWuUzXWXum+bjCGp8zDAum/7Tm
ZOALdV5uO8dv5ewQ9XOp6bsA
=e7Vg
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $signature = $this->gpg->verify($normalSignedData);
        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testVerifyClearsignedData()

    /**
     * @group verify
     */
    public function testVerifyClearsignedData()
    {
        // {{{ expected signature
        $expectedSignature = new Crypt_GPG_Signature();
        $expectedSignature->setId('mvtJs/XKU5KwDQ91YH0efv6vA7s');
        $expectedSignature->setKeyFingerprint(
            '5A58436F752BC80B3E992C1D300579D099645239');

        $expectedSignature->setCreationDate(1200674325);
        $expectedSignature->setExpirationDate(0);
        $expectedSignature->setIsValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Public and Private Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('public-and-private@example.com');
        $expectedSignature->setUserId($userId);
        // }}}
        // {{{ clearsigned data
        $clearsignedData = <<<TEXT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello, Alice! Goodbye, Bob!
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQFHkNYVMAV50JlkUjkRAtdgAKC2ZXyC/DByKea3PoUYXPGMVhRlFQCfVJWH
1NlgJvH0ScrfDpZhb0xKbxA=
=nI9H
-----END PGP SIGNATURE-----

TEXT;

        // }}}

        $signature = $this->gpg->verify($clearsignedData);
        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
    // {{{ testVerifyDetachedSignature()

    /**
     * @group verify
     */
    public function testVerifyDetachedSignature()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        // {{{ expected signature
        $expectedSignature = new Crypt_GPG_Signature();
        $expectedSignature->setId('0Wyj4MWXtqzVT6nvgEQ+De2sV6M');
        $expectedSignature->setKeyFingerprint(
            '5A58436F752BC80B3E992C1D300579D099645239');

        $expectedSignature->setCreationDate(1200674279);
        $expectedSignature->setExpirationDate(0);
        $expectedSignature->setIsValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Public and Private Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('public-and-private@example.com');
        $expectedSignature->setUserId($userId);
        // }}}
        // {{{ detached signature
        $detachedSignature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBHkNXnMAV50JlkUjkRAvDnAJ9TViHfxW127Clvh3y/2SmAIvKyfwCfeD/q
aLnxi+7N7THxsFSmpqLPRrQ=
=hawX
-----END PGP SIGNATURE-----

TEXT;

        // }}}

        $signature = $this->gpg->verify($data, $detachedSignature);
        $this->assertEquals($expectedSignature, $signature);
    }

    // }}}
}

?>
