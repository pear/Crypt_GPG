<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Verify tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
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
class VerifyTestCase extends Crypt_GPG_TestCase
{
    // string
    // {{{ testVerifyNoDataException_invalid()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testVerifyNoDataException_invalid()
    {
        $signedData = 'Invalid OpenPGP data.';
        $this->gpg->verify($signedData);
    }

    // }}}
    // {{{ testVerifyNoDataException_empty()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testVerifyNoDataException_empty()
    {
        $signedData = '';
        $this->gpg->verify($signedData);
    }

    // }}}
    // {{{ testVerifyKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testVerifyKeyNotFoundException()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        // {{{ detached signature
        $detachedSignature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBI1xN9CuJ9bDb23VARAkKSAKCG5/jPq1H7+mpMEpDITFnAJhSqlwCggzRx
laNWOZOef2zfm1yANtWjPyU=
=fhME
-----END PGP SIGNATURE-----

TEXT;
        // }}}
        $this->gpg->verify($data, $detachedSignature);
    }

    // }}}
    // {{{ testVerifyNormalSignedData()

    /**
     * @group string
     */
    public function testVerifyNormalSignedData()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('KuhELanvhPRXozEjFWb2mam1q20');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1221785858);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}
        // {{{ normal signed data
        $normalSignedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

owGbwMvMwCR4YPrNN1MOJCczrjFOEsrLL8pNzNEtzkzPS03RTUksSfS49JPJIzUn
J19HwTEnMzlVUcE9Pz8lqTJVR8EpP0mxw56ZlQGkBmaMIJO9GsOCo2L3pk5y2DNT
yiFKb0X03YSJqscaGRb0BKjZ3P+6SvjG160/WOa9vpey4QUDAA==
=wtCB
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $expectedSignatures = array($signature);

        $signatures = $this->gpg->verify($normalSignedData);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyClearsignedData()

    /**
     * @group string
     */
    public function testVerifyClearsignedData()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('wwm5gqNiFS+E/tmqbt1uXvVy3Ck');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1221785858);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}
        // {{{ clearsigned data
        $clearsignedData = <<<TEXT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello, Alice! Goodbye, Bob!
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQFI0vkCwJfZ7JTAY2MRAgzTAKCRecYZsCS+PE46Fa2QLTEP8XGLwwCfQEAL
qO+KlKcldtYdMZH9AA+KOLQ=
=EO2G
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($signature);

        $signatures = $this->gpg->verify($clearsignedData);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyDetachedSignature()

    /**
     * @group string
     */
    public function testVerifyDetachedSignature()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('E4HEDmMtecF457JFb88UAtPBVWY');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1221785858);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}
        // {{{ detached signature
        $detachedSignature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBI0vkCwJfZ7JTAY2MRAj8mAKC4IN01tGaEtNxWYS5eQiNT4Fua9ACeKum3
BdQ5rTOK2pp2X2vy/k2aCPo=
=upYI
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($signature);

        $signatures = $this->gpg->verify($data, $detachedSignature);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyDualNormalSignedData()

    /**
     * @group string
     */
    public function testVerifyDualNormalSignedData()
    {
        // {{{ first signature
        $firstSignature = new Crypt_GPG_Signature();
        $firstSignature->setId('4BunvSK18HPx6Xt4tEzyAqcNVzY');
        $firstSignature->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $firstSignature->setKeyId('03CC890AFA1DAD4B');
        $firstSignature->setCreationDate(1221785858);
        $firstSignature->setExpirationDate(0);
        $firstSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $firstSignature->setUserId($userId);
        // }}}
        // {{{ second signature
        $secondSignature = new Crypt_GPG_Signature();
        $secondSignature->setId('oAZ64v4sFarc7dssFOAJPB0D7zs');
        $secondSignature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $secondSignature->setKeyId('C097D9EC94C06363');
        $secondSignature->setCreationDate(1221785858);
        $secondSignature->setExpirationDate(0);
        $secondSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $secondSignature->setUserId($userId);
        // }}}
        // {{{ dual normal signed data
        $dualNormalSignedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

owGbwMvMwCR4YPrNN1MOJCczTABzmc90cv2SXevNuMYiSTylNDFHNy+/KBdIFWem
56Wm6KYkliR6XPrJ5JGak5Ovo+CYk5mcqqjgnp+fklSZqqPglJ+k2GHPzMoAUgMz
S5DJXo1hns0D5bkxpVHbI8+1y866l6K4yE1vHcNcOS1T45mf+VMn1NxQnnVn3Uab
dx7z4AbA3AY2YMGDvnnpCe982TwPTGyZdn+fMbu0fQDDgn098wSP/O79+/aYgon9
y/y/MVtYcwE=
=7EC6
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $expectedSignatures = array($firstSignature, $secondSignature);

        $signatures = $this->gpg->verify($dualNormalSignedData);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyDualClearsignedData()

    /**
     * @group string
     */
    public function testVerifyDualClearsignedData()
    {
        // {{{ first signature
        $firstSignature = new Crypt_GPG_Signature();
        $firstSignature->setId('MCn4/0Giq0njPh2smOs3Lrdc7yY');
        $firstSignature->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $firstSignature->setKeyId('03CC890AFA1DAD4B');
        $firstSignature->setCreationDate(1221785858);
        $firstSignature->setExpirationDate(0);
        $firstSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $firstSignature->setUserId($userId);
        // }}}
        // {{{ second signature
        $secondSignature = new Crypt_GPG_Signature();
        $secondSignature->setId('O5tcpOAXJhd0v5TBxqhIixgphn8');
        $secondSignature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $secondSignature->setKeyId('C097D9EC94C06363');
        $secondSignature->setCreationDate(1221785858);
        $secondSignature->setExpirationDate(0);
        $secondSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $secondSignature->setUserId($userId);
        // }}}
        // {{{ dual clearsigned data
        $dualClearsignedData = <<<TEXT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello, Alice! Goodbye, Bob!
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQFI0vkCA8yJCvodrUsRAgzTAJ9xSosvdq3fqaseRS6YV9VgnSGo2gCgiD+2
TRUrY67ZzdfTjCd6cFZHqauIPwMFAUjS+QLAl9nslMBjYxECDNMAoKdQQAWe8EwG
kZ/cCDE/fgToHk+7AJ9sU0NweUfUP3KNe2UK808Epd0Avg==
=j0ot
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($firstSignature, $secondSignature);

        $signatures = $this->gpg->verify($dualClearsignedData);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyDualDetachedSignature()

    /**
     * @group string
     */
    public function testVerifyDualDetachedSignature()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        // {{{ first signature
        $firstSignature = new Crypt_GPG_Signature();
        $firstSignature->setId('tejKd9+9OBUM+EsrbV3fVuOiBeE');
        $firstSignature->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $firstSignature->setKeyId('03CC890AFA1DAD4B');
        $firstSignature->setCreationDate(1221785858);
        $firstSignature->setExpirationDate(0);
        $firstSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $firstSignature->setUserId($userId);
        // }}}
        // {{{ second signature
        $secondSignature = new Crypt_GPG_Signature();
        $secondSignature->setId('7oizks/aha+bSONesnWDu1x2jn8');
        $secondSignature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $secondSignature->setKeyId('C097D9EC94C06363');
        $secondSignature->setCreationDate(1221785858);
        $secondSignature->setExpirationDate(0);
        $secondSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $secondSignature->setUserId($userId);
        // }}}
        // {{{ dual detached signature
        $dualDetachedSignature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBI0vkCA8yJCvodrUsRAj8mAKCJWz3ANeG9SPGUHMg04gH0rCOqKwCfaxUR
Dypdcanj3VE3inTxleaQtdqIPwMFAEjS+QLAl9nslMBjYxECPyYAoN+Y3tibHIg+
9+fdvxAEvANir2RQAKCuD2BsKzSmyV3G4/i6oPNhOrwtPg==
=8P1D
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($firstSignature, $secondSignature);

        $signatures = $this->gpg->verify($data, $dualDetachedSignature);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyBadSignature()

    /**
     * @group string
     */
    public function testVerifyBadSignature()
    {
        $modifiedData = 'Hello, Bob! Goodbye, Alice!';

        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setKeyId('C097D9EC94C06363');
        $signature->setValid(false);
        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}
        // {{{ detached signature
        $detachedSignature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBI0vkCwJfZ7JTAY2MRAj8mAKC4IN01tGaEtNxWYS5eQiNT4Fua9ACeKum3
BdQ5rTOK2pp2X2vy/k2aCPo=
=upYI
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($signature);

        $signatures = $this->gpg->verify($modifiedData, $detachedSignature);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyDualBadSignatures()

    /**
     * @group string
     */
    public function testVerifyDualBadSignatures()
    {
        $modifiedData = 'Hello, Bob! Goodbye, Alice!';

        // {{{ first signature
        $firstSignature = new Crypt_GPG_Signature();
        $firstSignature->setExpirationDate(0);
        $firstSignature->setValid(false);
        $firstSignature->setKeyId('03CC890AFA1DAD4B');
        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $firstSignature->setUserId($userId);
        // }}}
        // {{{ second signature
        $secondSignature = new Crypt_GPG_Signature();
        $secondSignature->setValid(false);
        $secondSignature->setKeyId('C097D9EC94C06363');
        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $secondSignature->setUserId($userId);
        // }}}
        // {{{ dual detached signature
        $dualDetachedSignature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBI0vkCA8yJCvodrUsRAj8mAKCJWz3ANeG9SPGUHMg04gH0rCOqKwCfaxUR
Dypdcanj3VE3inTxleaQtdqIPwMFAEjS+QLAl9nslMBjYxECPyYAoN+Y3tibHIg+
9+fdvxAEvANir2RQAKCuD2BsKzSmyV3G4/i6oPNhOrwtPg==
=8P1D
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($firstSignature, $secondSignature);

        $signatures = $this->gpg->verify($modifiedData, $dualDetachedSignature);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyFileNormalSignedData()

    /**
     * @group file
     */
    public function testVerifyFileNormalSignedData()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('vctnI/HnsRYmqcVwCJcJhS60lKU');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1221960707);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedSignatures = array($signature);

        $filename =
            $this->getDataFilename('testVerifyFileNormalSignedData.asc');

        $signatures = $this->gpg->verifyFile($filename);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyFileClearsignedData()

    /**
     * @group file
     */
    public function testVerifyFileClearsignedData()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('6sXJXKZB5lvRSCXBAYl6R2EiDmw');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1221960707);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedSignatures = array($signature);

        $filename = $this->getDataFilename('testVerifyFileClearsignedData.asc');

        $signatures = $this->gpg->verifyFile($filename);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyFileDetachedSignature()

    /**
     * @group file
     */
    public function testVerifyFileDetachedSignature()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('tdsH/ulxOnoWEMPDamZTq7wzF/0');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1221960707);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}
        // {{{ signatureData
        $signatureData = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBI1aQDwJfZ7JTAY2MRAvkzAJ0RAW0wtlfEgDccgq+N5IgbpA4BOQCfS8vV
Of32/RcteCLdt73awNJ0CwI=
=RVco
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($signature);

        $filename = $this->getDataFilename('testFileMedium.plain');

        $signatures = $this->gpg->verifyFile($filename, $signatureData);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyFileDualNormalSignedData()

    /**
     * @group file
     */
    public function testVerifyFileDualNormalSignedData()
    {
        // {{{ first signature
        $firstSignature = new Crypt_GPG_Signature();
        $firstSignature->setId('Kl3Mds4ABT9JyE3iqfPGpUHzKQs');
        $firstSignature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $firstSignature->setKeyId('C097D9EC94C06363');
        $firstSignature->setCreationDate(1221960707);
        $firstSignature->setExpirationDate(0);
        $firstSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $firstSignature->setUserId($userId);
        // }}}
        // {{{ second signature
        $secondSignature = new Crypt_GPG_Signature();
        $secondSignature->setId('KGrEm3hGqiKaLbjvOUO9kvUjRXc');
        $secondSignature->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $secondSignature->setKeyId('03CC890AFA1DAD4B');
        $secondSignature->setCreationDate(1221960707);
        $secondSignature->setExpirationDate(0);
        $secondSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $secondSignature->setUserId($userId);
        // }}}

        $expectedSignatures = array($firstSignature, $secondSignature);

        $filename =
            $this->getDataFilename('testVerifyFileDualNormalSignedData.asc');

        $signatures = $this->gpg->verifyFile($filename);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyFileDualClearsignedData()

    /**
     * @group file
     */
    public function testVerifyFileDualClearsignedData()
    {
        // {{{ first signature
        $firstSignature = new Crypt_GPG_Signature();
        $firstSignature->setId('eRRcEecpFk0YK/iswddS/KBxEXI');
        $firstSignature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $firstSignature->setKeyId('C097D9EC94C06363');
        $firstSignature->setCreationDate(1221960707);
        $firstSignature->setExpirationDate(0);
        $firstSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $firstSignature->setUserId($userId);
        // }}}
        // {{{ second signature
        $secondSignature = new Crypt_GPG_Signature();
        $secondSignature->setId('jsWYGJe/0hmte7tYt8zuJd7rFMM');
        $secondSignature->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $secondSignature->setKeyId('03CC890AFA1DAD4B');
        $secondSignature->setCreationDate(1221960707);
        $secondSignature->setExpirationDate(0);
        $secondSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $secondSignature->setUserId($userId);
        // }}}

        $expectedSignatures = array($firstSignature, $secondSignature);

        $filename =
            $this->getDataFilename('testVerifyFileDualClearsignedData.asc');

        $signatures = $this->gpg->verifyFile($filename);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);
    }

    // }}}
    // {{{ testVerifyFileDualDetachedSignature()

    /**
     * @group file
     */
    public function testVerifyFileDualDetachedSignature()
    {
        // {{{ first signature
        $firstSignature = new Crypt_GPG_Signature();
        $firstSignature->setId('T7+toJbsFr8KMTWN+M7lF3xSmmA');
        $firstSignature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $firstSignature->setKeyId('C097D9EC94C06363');
        $firstSignature->setCreationDate(1221960707);
        $firstSignature->setExpirationDate(0);
        $firstSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $firstSignature->setUserId($userId);
        // }}}
        // {{{ second signature
        $secondSignature = new Crypt_GPG_Signature();
        $secondSignature->setId('HJd1yvMbEbW5facuxkDtvwymKrw');
        $secondSignature->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $secondSignature->setKeyId('03CC890AFA1DAD4B');
        $secondSignature->setCreationDate(1221960707);
        $secondSignature->setExpirationDate(0);
        $secondSignature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('Second Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('second-keypair@example.com');
        $secondSignature->setUserId($userId);
        // }}}
        // {{{ signature data
        $signatureData = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBI1aQDwJfZ7JTAY2MRAvkzAKDPnJ030GdYE15mE8smz2oV7zYziwCeJFxf
UaTrAgP1Dck9DhHOBhvhwLuIPwMFAEjVpAMDzIkK+h2tSxEC+TMAn38yx3mXk6wP
JaPThD7lRVE9ve57AJ0Yy7JwiT9sGXomln4JtRvuSpGtsg==
=Gw9D
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $expectedSignatures = array($firstSignature, $secondSignature);

        $filename = $this->getDataFilename('testFileMedium.plain');

        $signatures = $this->gpg->verifyFile($filename, $signatureData);
        $this->assertSignaturesEquals($expectedSignatures, $signatures);

        $warnings = $this->gpg->getWarnings();
        $this->assertTrue(is_array($warnings));
    }

    // }}}
    // {{{ testVerifyFileFileException()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testVerifyFileFileException()
    {
        $filename = './non-existent/testVerifyFileFileException.asc';
        $this->gpg->verifyFile($filename);
    }

    // }}}
    // {{{ testVerifyFileNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group file
     */
    public function testVerifyFileNoDataException()
    {
        $filename = $this->getDataFilename('testFileEmpty.plain');
        $this->gpg->verifyFile($filename);
    }

    // }}}
}

?>
