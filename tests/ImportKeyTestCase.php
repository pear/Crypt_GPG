<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key import tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit ImportKeyTestCase
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
 * Tests key import abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class ImportKeyTestCase extends TestCase
{
    // {{{ testImportKeyPrivateKey()

    /**
     * @group import
     */
    public function testImportKeyPrivateKey()
    {
        $expectedResult = array(
            'fingerprint'       => 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4',
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        // {{{ private key data
        $privateKeyData = <<<TEXT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

lQHhBEeQxv0RBAD+cWerD9h+b135x1/m5NWuwpUNpkE7Be4X8PxpwuAHDN2B2QK4
fGF1XWP70RMcvKNx7xR/fbQ25jaHuWPxrxolUADJJwwUqpRZq/ObGo3NWhldVsm2
iU5M2KMwc6D5XQICObyOe9WUJ7HNGKNPclNQzFyhaOA0JcQN+mTlnfwfGwCg2vuY
PzLDcmnyQCdggKLZDy4uARsEALmZFCQQ4SIvLR7IXI+GzhsRkMcNZdqUPLjPhCgl
Fsfigt+o8AGG7wqmkSnqyf+387RYaUB1b7FAZBecYLjnHPC1JCaZ9QZpklibCN9G
3Mii2jF3nogX+OsCJK0q0MFTBjxp1xkqeBoERf9ZUMEw+/j9oCbETTUjzKtTH/MU
YHH/BADKIsdTvwrmkoMXaRIpzGT8UjHwcb8Ao1DrqWxXtaGmf7IJaMiS5bHu2Mv4
0B76G3nEqz6vtSCDsMKH8W5VwDLxnqRe4Tz23gkaKA0fR3PtJw8iuMwGREgEssEM
IJ+Ox7Lc6anHrMqmEafTgsszuO7Y6KMgJ9W6yz+D68OIFlDimf4DAwLzRN+MlalC
IGAgIiUrV+3rD9PkemIkao2URO2ScPYSntabQ1Pv9YDDpzLEki+40/7m+F6hpBtP
PF/mALRcUHVibGljIE9ubHkgVGVzdCBLZXkgKGRvIG5vdCBlbmNyeXB0IGltcG9y
dGFudCBkYXRhIHdpdGggdGhpcyBrZXkpIDxwdWJsaWMtb25seUBleGFtcGxlLmNv
bT6IYAQTEQIAIAUCR5DG/QIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEBbS
dFixu6HEKq8An2DtKGLVqZ8dzP5MQRq/qw8Zc38eAKCa4g5Z5qckRTm5GunPDPMw
54P/5Z0CYwRHkMcGEAgAok+tFuvdGK4HHDKGDHCy7VSUNGibyy04YFOdOHyx+doj
OVroeCeKIgWhOGIEFGpfmHf3PwUvD0MD91Co1kifTm0LMvUSFNgqW2/5wgfzgmKN
vqQbxwHuVAzwKdqxJJRDWNusQAif8Ch8q8jTeGmCJJM84xZoduaMKz/wKP2XAgKf
701CC9nh0XJzaB6Nc8CO6lBMRf/wzKcGFPy0wiTiuwIC9vSt4yfkwmz0SgndTJtI
JjBrTRSF+gEtkjECIO7U1mCUnjcnn/vm60Ij1r/xlttfkkeML/Hmlj2HNQ8sk2qF
qRpf3oVggovyYt6/Xm2/j0iIQm5aQ3793sb1DfXrSwADBgf9G5D9rUdOQauoCxK0
oXPpqbohC3vLpiEzN2qEjqdt5NVQB/vsPG/4Dzt0Jr5gcRt6DzJ9rDvNY6saTmv1
T2LSTm4a6mDoZk2+LGl0qWCiMvkKlyLTXR61LGIypX2175yzkDEs9KfY+pExZBd/
WnkN3xrhTXWgY/i5Ul4CpU6sE5Kx4cGvioNDE80tMnAI/5mg1Q++fPs8w0Nh1ZGD
PHVkyNJpureBWVkMDQ5zLn89UMm7wMeNBCNksvt5m5+JzA0t70Dp87khJtbfjADd
3MlfX/Fu3w1kfIM6C9j+xfyAdk/UtMEmEJiYOLziamHI90TZdHXQgV+/b8BLjgYA
CGQG6P4DAwLzRN+MlalCIGCm+u6eYnTE4oBCsQBnknxohqmrSc7MrJXSATR5hStG
iAhpmQUtqZgtbFKm7SjfaMlNVo7mvs89GuMFp1DH3iElZEh05wULfHiQiEkEGBEC
AAkFAkeQxwYCGwwACgkQFtJ0WLG7ocTOTgCfXR4Ycnkz9Pa4/IOCryHUmDD06kAA
oI5UEei5MOBXWqSclNRONxPG8GL/
=b5iz
-----END PGP PRIVATE KEY BLOCK-----

TEXT;
        // }}}

        $result =  $this->gpg->importKey($privateKeyData);
        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyPublicKey()

    /**
     * @group import
     */
    public function testImportKeyPublicKey()
    {
        $expectedResult = array(
            'fingerprint'       => '0E8920DF5E2F5FD15A3BC3F14636F589A551E85A',
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        // {{{ public key data
        $publicKeyData = <<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

mQGiBEeQynIRBACeQvsqqxtU7gnWGIhFCl//KOjSeWe9iwuj1KkXR9yu2I17/YHi
fU7StVH3wTSw+kPvBJfQlDrYafqD1KUogakl9IN6bnnfDVUnUFZ00PNj9VGrCGR/
IRxM2DZpy2KvFq0MDfo5yqtFBOol1bi2NgHu3gEXafqbAP7kzScjPv93ZwCg6Fad
vOBSOHq8wCcJ32531EkCGKUEAJozX9Gsj9y/1zKMdc4ZrdciemseiZ8Ua/GSIBUM
eC8FcaDcfjSvv9yiA3+CsYkiJZv0et6xnsnW5/cnCBdLck0mciRIWf9/0U6eM30W
ElsWUfL4xdA/g28EdJSU16n0KpJzZx77gL2dGFz9M4GoG654JfFTXz4ins9iiZs2
+rCrA/4tkhtc7lp3Y2zlE4nZyXM+fA6mupAkPGsAK/yk61zXfk6LvxCSyO6kgOMn
E2RHrt4MG16OfNO/Ak7zPtlLRQmkmV2OZFZ5r5uiRMfXBCgYeSjdWAXueCCCGIdF
dp4y7zlIrsTYZ3VUXq3Zho8Ah37smEJvfgkO4bccex+YUUVwfLRkRXh0ZXJuYWwg
UHVibGljIFRlc3QgS2V5IChkbyBub3QgZW5jcnlwdCBpbXBvcnRhbnQgZGF0YSB3
aXRoIHRoaXMga2V5KSA8ZXh0ZXJuYWwtcHVibGljQGV4YW1wbGUuY29tPohgBBMR
AgAgBQJHkMpyAhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQRjb1iaVR6FqL
dQCfdCsfRccq5b6/DuyOyykOe8QGgRQAn3jb39ySfFcKq1TenPWkVRxeaW4ruQIN
BEeQyncQCACNaHdyLnWsHEh66fN+RLL7WxGVEcBIeD4zOiORExfpDb0TieYy9UfF
VC7JNRWjXqz0eSwfbnJqz6RmW9RZKN59FEJ9LHUamTYJNtktCymjjgbA9ilBDuLC
dY64/0HwRsl01cJCYMXZrsTj3KUFoMMQdIT7KXclOiEEbqjL7YyprdZK8mEaZyOa
disDoghi4lrMqjN17ULk+Zfp9cmyi23EWnNDpIvLEorj5C+CYCvKnfhCYlPDUreX
ZPt2wCPqFzF3iCs63j51IYLFdtQqvH8zfCYR/KcbahR8h5HuQAuf2NSFeffqw1f/
iHKSvr9vkDlXCD3ZNjNe6HkehxKrcmAPAAMFB/4lMO+zGQ9fOLsfR5wiI0u4g1xO
Cb7ay4nmKvQAkgkrp+j713cc/3TjftcxjAmsB3Ns4Sux6iZsKH45HsfTNab4TBfE
PMrA+lS7nvleEsI/W94sIEOVB9EjXW5//bNx54Nm5AHgioLPHYSQPv40fKKRuWEj
r/hg2HgZrccYLhxOLNrR3vKKV8jCqIp1cjn5LdbWsacvGoPsiBRQFBDBhvlAbe6W
4sYky1XmFkI6LgYnqMJxNuBV50B/IgK32CPXqsGDu9rUcmJQAvSvr0RKBJYwOE5I
ij9I0i6vNrPnAOqih0xABq9E8RYHnGYg3Vnww2z9/crLvN2jJ2Ow8ubM3RyGiEkE
GBECAAkFAkeQyncCGwwACgkQRjb1iaVR6FoX2ACgnfXsfawe5Ys2Zp3b0/H+zkFa
Y0kAn0UNciBVQN54ii7SEg/LzJOyPbSS
=QT0F
-----END PGP PUBLIC KEY BLOCK-----

TEXT;
        // }}}

        $result = $this->gpg->importKey($publicKeyData);
        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyPublicKeyAlreadyImported()

    /**
     * @group import
     */
    public function testImportKeyPublicKeyAlreadyImported()
    {
        // {{{ public key data
        $publicKeyData = <<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

mQGiBEeQynIRBACeQvsqqxtU7gnWGIhFCl//KOjSeWe9iwuj1KkXR9yu2I17/YHi
fU7StVH3wTSw+kPvBJfQlDrYafqD1KUogakl9IN6bnnfDVUnUFZ00PNj9VGrCGR/
IRxM2DZpy2KvFq0MDfo5yqtFBOol1bi2NgHu3gEXafqbAP7kzScjPv93ZwCg6Fad
vOBSOHq8wCcJ32531EkCGKUEAJozX9Gsj9y/1zKMdc4ZrdciemseiZ8Ua/GSIBUM
eC8FcaDcfjSvv9yiA3+CsYkiJZv0et6xnsnW5/cnCBdLck0mciRIWf9/0U6eM30W
ElsWUfL4xdA/g28EdJSU16n0KpJzZx77gL2dGFz9M4GoG654JfFTXz4ins9iiZs2
+rCrA/4tkhtc7lp3Y2zlE4nZyXM+fA6mupAkPGsAK/yk61zXfk6LvxCSyO6kgOMn
E2RHrt4MG16OfNO/Ak7zPtlLRQmkmV2OZFZ5r5uiRMfXBCgYeSjdWAXueCCCGIdF
dp4y7zlIrsTYZ3VUXq3Zho8Ah37smEJvfgkO4bccex+YUUVwfLRkRXh0ZXJuYWwg
UHVibGljIFRlc3QgS2V5IChkbyBub3QgZW5jcnlwdCBpbXBvcnRhbnQgZGF0YSB3
aXRoIHRoaXMga2V5KSA8ZXh0ZXJuYWwtcHVibGljQGV4YW1wbGUuY29tPohgBBMR
AgAgBQJHkMpyAhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQRjb1iaVR6FqL
dQCfdCsfRccq5b6/DuyOyykOe8QGgRQAn3jb39ySfFcKq1TenPWkVRxeaW4ruQIN
BEeQyncQCACNaHdyLnWsHEh66fN+RLL7WxGVEcBIeD4zOiORExfpDb0TieYy9UfF
VC7JNRWjXqz0eSwfbnJqz6RmW9RZKN59FEJ9LHUamTYJNtktCymjjgbA9ilBDuLC
dY64/0HwRsl01cJCYMXZrsTj3KUFoMMQdIT7KXclOiEEbqjL7YyprdZK8mEaZyOa
disDoghi4lrMqjN17ULk+Zfp9cmyi23EWnNDpIvLEorj5C+CYCvKnfhCYlPDUreX
ZPt2wCPqFzF3iCs63j51IYLFdtQqvH8zfCYR/KcbahR8h5HuQAuf2NSFeffqw1f/
iHKSvr9vkDlXCD3ZNjNe6HkehxKrcmAPAAMFB/4lMO+zGQ9fOLsfR5wiI0u4g1xO
Cb7ay4nmKvQAkgkrp+j713cc/3TjftcxjAmsB3Ns4Sux6iZsKH45HsfTNab4TBfE
PMrA+lS7nvleEsI/W94sIEOVB9EjXW5//bNx54Nm5AHgioLPHYSQPv40fKKRuWEj
r/hg2HgZrccYLhxOLNrR3vKKV8jCqIp1cjn5LdbWsacvGoPsiBRQFBDBhvlAbe6W
4sYky1XmFkI6LgYnqMJxNuBV50B/IgK32CPXqsGDu9rUcmJQAvSvr0RKBJYwOE5I
ij9I0i6vNrPnAOqih0xABq9E8RYHnGYg3Vnww2z9/crLvN2jJ2Ow8ubM3RyGiEkE
GBECAAkFAkeQyncCGwwACgkQRjb1iaVR6FoX2ACgnfXsfawe5Ys2Zp3b0/H+zkFa
Y0kAn0UNciBVQN54ii7SEg/LzJOyPbSS
=QT0F
-----END PGP PUBLIC KEY BLOCK-----

TEXT;
        // }}}

        $result = $this->gpg->importKey($publicKeyData);

        $expectedResult = array(
            'fingerprint'       => '0E8920DF5E2F5FD15A3BC3F14636F589A551E85A',
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);

        $result = $this->gpg->importKey($publicKeyData);

        $expectedResult = array(
            'fingerprint'       => '0E8920DF5E2F5FD15A3BC3F14636F589A551E85A',
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyPrivateKeyAlreadyImported()

    /**
     * @group import
     */
    public function testImportKeyPrivateKeyAlreadyImported()
    {
        // {{{ private key data
        $privateKeyData = <<<TEXT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

lQHhBEeQxv0RBAD+cWerD9h+b135x1/m5NWuwpUNpkE7Be4X8PxpwuAHDN2B2QK4
fGF1XWP70RMcvKNx7xR/fbQ25jaHuWPxrxolUADJJwwUqpRZq/ObGo3NWhldVsm2
iU5M2KMwc6D5XQICObyOe9WUJ7HNGKNPclNQzFyhaOA0JcQN+mTlnfwfGwCg2vuY
PzLDcmnyQCdggKLZDy4uARsEALmZFCQQ4SIvLR7IXI+GzhsRkMcNZdqUPLjPhCgl
Fsfigt+o8AGG7wqmkSnqyf+387RYaUB1b7FAZBecYLjnHPC1JCaZ9QZpklibCN9G
3Mii2jF3nogX+OsCJK0q0MFTBjxp1xkqeBoERf9ZUMEw+/j9oCbETTUjzKtTH/MU
YHH/BADKIsdTvwrmkoMXaRIpzGT8UjHwcb8Ao1DrqWxXtaGmf7IJaMiS5bHu2Mv4
0B76G3nEqz6vtSCDsMKH8W5VwDLxnqRe4Tz23gkaKA0fR3PtJw8iuMwGREgEssEM
IJ+Ox7Lc6anHrMqmEafTgsszuO7Y6KMgJ9W6yz+D68OIFlDimf4DAwLzRN+MlalC
IGAgIiUrV+3rD9PkemIkao2URO2ScPYSntabQ1Pv9YDDpzLEki+40/7m+F6hpBtP
PF/mALRcUHVibGljIE9ubHkgVGVzdCBLZXkgKGRvIG5vdCBlbmNyeXB0IGltcG9y
dGFudCBkYXRhIHdpdGggdGhpcyBrZXkpIDxwdWJsaWMtb25seUBleGFtcGxlLmNv
bT6IYAQTEQIAIAUCR5DG/QIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEBbS
dFixu6HEKq8An2DtKGLVqZ8dzP5MQRq/qw8Zc38eAKCa4g5Z5qckRTm5GunPDPMw
54P/5Z0CYwRHkMcGEAgAok+tFuvdGK4HHDKGDHCy7VSUNGibyy04YFOdOHyx+doj
OVroeCeKIgWhOGIEFGpfmHf3PwUvD0MD91Co1kifTm0LMvUSFNgqW2/5wgfzgmKN
vqQbxwHuVAzwKdqxJJRDWNusQAif8Ch8q8jTeGmCJJM84xZoduaMKz/wKP2XAgKf
701CC9nh0XJzaB6Nc8CO6lBMRf/wzKcGFPy0wiTiuwIC9vSt4yfkwmz0SgndTJtI
JjBrTRSF+gEtkjECIO7U1mCUnjcnn/vm60Ij1r/xlttfkkeML/Hmlj2HNQ8sk2qF
qRpf3oVggovyYt6/Xm2/j0iIQm5aQ3793sb1DfXrSwADBgf9G5D9rUdOQauoCxK0
oXPpqbohC3vLpiEzN2qEjqdt5NVQB/vsPG/4Dzt0Jr5gcRt6DzJ9rDvNY6saTmv1
T2LSTm4a6mDoZk2+LGl0qWCiMvkKlyLTXR61LGIypX2175yzkDEs9KfY+pExZBd/
WnkN3xrhTXWgY/i5Ul4CpU6sE5Kx4cGvioNDE80tMnAI/5mg1Q++fPs8w0Nh1ZGD
PHVkyNJpureBWVkMDQ5zLn89UMm7wMeNBCNksvt5m5+JzA0t70Dp87khJtbfjADd
3MlfX/Fu3w1kfIM6C9j+xfyAdk/UtMEmEJiYOLziamHI90TZdHXQgV+/b8BLjgYA
CGQG6P4DAwLzRN+MlalCIGCm+u6eYnTE4oBCsQBnknxohqmrSc7MrJXSATR5hStG
iAhpmQUtqZgtbFKm7SjfaMlNVo7mvs89GuMFp1DH3iElZEh05wULfHiQiEkEGBEC
AAkFAkeQxwYCGwwACgkQFtJ0WLG7ocTOTgCfXR4Ycnkz9Pa4/IOCryHUmDD06kAA
oI5UEei5MOBXWqSclNRONxPG8GL/
=b5iz
-----END PGP PRIVATE KEY BLOCK-----

TEXT;
        // }}}

        $result = $this->gpg->importKey($privateKeyData);

        $expectedResult = array(
            'fingerprint'       => 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4',
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        $this->assertEquals($expectedResult, $result);

        $result = $this->gpg->importKey($privateKeyData);

        $expectedResult = array(
            'fingerprint'       => 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4',
            'public_imported'   => 0,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 1
        );

        $this->assertEquals($expectedResult, $result);
    }

    // }}}
    // {{{ testImportKeyNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group import
     */
    public function testImportKeyNoDataException()
    {
        $keyData = 'Invalid OpenPGP data.';
        $this->gpg->importKey($keyData);
    }

    // }}}
}

?>
