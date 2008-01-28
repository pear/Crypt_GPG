<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * PHPUnit3.2 test framework script for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit PhpDriver
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
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * PHPUnit3 framework
 */
require_once 'PHPUnit/Framework.php';

/**
 * The Crypt_GPG class to test
 */
require_once 'Crypt/GPG.php';

/**
 * Tests the native PHP implementation of the Crypt_GPG object.
 *
 * Test keyring contains:
 *
 * 1) public-and-private@example.com - passphrase 'test'
 *    A public-private key pair that can be used to both encrypt and decrypt.
 *
 * 2) public-only@example.com - passphrase 'test'
 *    A public key with no private key. Used for testing private key import.
 *
 * 3) no-passphrase@example.com - no passphrase
 *    A public-private key pair that can be used to both encrypt and decrypt
 *    with no passphrase.
 *
 * 4) external-public@example.com - passphrase 'test'
 *    A public key that does not initially exist in the keyring that can be
 *    imported.
 */
class PhpDriver extends PHPUnit_Framework_TestCase
{
    // {{{ class constants

    const HOMEDIR = './test-keychain';

    // }}}
    // {{{ private properties

    private $_gpg;

    // }}}
    // {{{ setUp()

    public function setUp()
    {
        // {{{ pubring data
        $pubring_data = <<<TEXT
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
rOENIDpNsfp3F0p+noT8sJ/DCf78vOnFK5+uM//P+0bHnQAL/eetDM3mqnCQ
iIBfLeBcDeYEAI+Dnyfs5ckuOliIvJdvP61UHvNhQHAdbh7gmtbwyIQT6epP
H7bMmaO1ilob95i/7fYlUGv71bTEnSmAYaI8zEZD1byS/h2CkYacB3m8vAYJ
JjwbRPcTmR0tD6r64//u7ZTUzVZhmuO7jc/fGtpYj/mCP5icmiY+XJ1oHfy2
I8z7tHNObyBQYXNzcGhyYXNlIFB1YmxpYyBhbmQgUHJpdmF0ZSBUZXN0IEtl
eSAoZG8gbm90IGVuY3J5cHQgaW1wb3J0YW50IGRhdGEgd2l0aCB0aGlzIGtl
eSkgPG5vLXBhc3NwaHJhc2VAZXhhbXBsZS5jb20+iGAEExECACAFAkeQybkC
GwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRDLJAcv72ZdFzXrAJ9cL+xb
Q+Ivik3q9TSpPnQ4rxn5uACfRI2ooTByIH9qV6Y9WhVUT/c4XU2wAgADuQIN
BEeQycQQCADJB67roIZFyCbvD0HA4rxu98cnseZgd3Prunmsvq/Qa1Hfkd4R
ZrcX4bd8txKjjaNio/PHWeijm3I1WqHgpobLTbROdudDnXYuqPKRYHy7CfNv
dlb5Qfeyr+0jOsKCdMkkhZ28rWQp7qO/lCl019w5Itq1gKPx8W7cuJbTeteW
V+Gna8hz3/Jn45f6CHYmcDP4T9OHlOPD8Tf3INQ32kd6PxrfhW7f5KG+itJ9
7Grx4QQnxVd2gh7s3dVM+L/f4cPppsSIBS0d+iBQ6wzCqaXOishFSSg/2upl
IJ5y08vXgaTUsGqLBePHx4ZUH6rJiL97b7RVTG9tOs3dVJAynRUDAAMFCACJ
ooMEUj2xSKadmi6fhcuXQ4VvhsDCErpAM8e10i3U7sN95bVWI7EMSxWbwBuN
elu+ntRZO3+VmE0fQ7X8tWPKBp9wxqu8pvaQvTO3oNLqNm/AhX6PQYohFopI
DVQKvJP71ZBiWfOxh9IXGbO2i91nyr2EiestrHXnBy5D66ePIoWsCFk03OCr
z9rxAh1UpVJUaHeJ76BZxj+jfg2blNSjJTilEJpMXlK898j0XMGShLSvZH/d
VwSHhXl+C6GMYhUGh6t9B42O+geMfj7M7iGYnYr28Af5S3Er/COF7gMJhTpr
46TxHvWyJ0G7w9GXBKvYupuo8E5HZ5dtKjaydrA6iEkEGBECAAkFAkeQycQC
GwwACgkQyyQHL+9mXReAjwCfaVnifK3G6Ij3kZ6b7IMPZO/po7EAn0tCWGtB
ALpDXpcmW7C6yHrUbWmUsAIAAw==

TEXT;
        // }}}
        // {{{ secring data
        $secring_data = <<<TEXT
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
nWgd/LYjzPsAAJ9cAw6U2OMIMHEbkgVtL6cD/OhfJwhmtHNObyBQYXNzcGhy
YXNlIFB1YmxpYyBhbmQgUHJpdmF0ZSBUZXN0IEtleSAoZG8gbm90IGVuY3J5
cHQgaW1wb3J0YW50IGRhdGEgd2l0aCB0aGlzIGtleSkgPG5vLXBhc3NwaHJh
c2VAZXhhbXBsZS5jb20+iGAEExECACAFAkeQybkCGwMGCwkIBwMCBBUCCAME
FgIDAQIeAQIXgAAKCRDLJAcv72ZdFzXrAJ9cL+xbQ+Ivik3q9TSpPnQ4rxn5
uACfRI2ooTByIH9qV6Y9WhVUT/c4XU2wAgAAnQI9BEeQycQQCADJB67roIZF
yCbvD0HA4rxu98cnseZgd3Prunmsvq/Qa1Hfkd4RZrcX4bd8txKjjaNio/PH
Weijm3I1WqHgpobLTbROdudDnXYuqPKRYHy7CfNvdlb5Qfeyr+0jOsKCdMkk
hZ28rWQp7qO/lCl019w5Itq1gKPx8W7cuJbTeteWV+Gna8hz3/Jn45f6CHYm
cDP4T9OHlOPD8Tf3INQ32kd6PxrfhW7f5KG+itJ97Grx4QQnxVd2gh7s3dVM
+L/f4cPppsSIBS0d+iBQ6wzCqaXOishFSSg/2uplIJ5y08vXgaTUsGqLBePH
x4ZUH6rJiL97b7RVTG9tOs3dVJAynRUDAAMFCACJooMEUj2xSKadmi6fhcuX
Q4VvhsDCErpAM8e10i3U7sN95bVWI7EMSxWbwBuNelu+ntRZO3+VmE0fQ7X8
tWPKBp9wxqu8pvaQvTO3oNLqNm/AhX6PQYohFopIDVQKvJP71ZBiWfOxh9IX
GbO2i91nyr2EiestrHXnBy5D66ePIoWsCFk03OCrz9rxAh1UpVJUaHeJ76BZ
xj+jfg2blNSjJTilEJpMXlK898j0XMGShLSvZH/dVwSHhXl+C6GMYhUGh6t9
B42O+geMfj7M7iGYnYr28Af5S3Er/COF7gMJhTpr46TxHvWyJ0G7w9GXBKvY
upuo8E5HZ5dtKjaydrA6AAFSAznmzNMYN/pRmdZyPYDj0SDzOL9UuN0sW6o4
9qvRlNXKrnWaMsDoTthY1RjriEkEGBECAAkFAkeQycQCGwwACgkQyyQHL+9m
XReAjwCgs8If0f3fKbVxLDb6/OtJF2zq7L0AoIiL1B3e+F0HebF7QaR06lGT
bgVPsAIAAA==

TEXT;
        // }}}
        // {{{ trustdb data
        $trustdb_data = <<<TEXT
AWdwZwMDAQUBAAAAR5DK0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAB4AAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAIgAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAIAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAk
AAAAAAAAACYAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADABaWENvdSvICz6ZLB0w
BXnQmWRSOQYAAAAAAAAfAAAAAAAAAAAAAA0AZc7E640LDHDv3b7mNJWdJkzU
R/sGAAAAAAAAAAAAAAAAAAAAAAAMAMO8YVrZx2blqFwfJxbSdFixu6HEBgAA
AAAAACEAAAAAAAAAAAAADQDEdwZbDHq3MsJkvFUMflgUcM0sawYAAAAAAAAA
AAAAAAAAAAAAAAwAiijGKCqJRsHV529rTsT566hV3wsAAAAAAAAAIwAAAAAA
AAAAAAANAKbgcq125tj9wZ4CZmtuS4PAbcN7AAAAAAAAAAAAAAAAAAAAAAAA
DADVcwAsHz6t+1iGhvcR8kmnOxa6RQAAAAAAAAAlAAAAAAAAAAAAAA0AnulI
6lkWYWYduR/JuNFYxJjqPsIAAAAAAAAAAAAAAAAAAAAAAAAMANcp6ATdUAEp
AiMoRcskBy/vZl0XBgAAAAAAACcAAAAAAAAAAAAADQD5eKGiTPFvlhgXYfzO
3peNMedvmgYAAAAAAAAAAAAAAAAAAAAAAAwADokg314vX9FaO8PxRjb1iaVR
6FoAAAAAAAAAKQAAAAAAAAAAAAANAH6Tzb+Rc+QDwSK63C/wHvL8pC6LAAAA
AAAAAAAAAAAAAAAAAAAA

TEXT;
        // }}}
        // {{{ random_seed data
        $random_seed_data = <<<TEXT
p1KYXATR1wfjZgXqGMBG9Wb3fQ7ExENWKnXNVzQP/1W+IYB8KDyEYsY4VgD0
CaG0jSFERkTCMR2CX1nTIyaQqVlPvLLjEzLIcjcESz+wXBP7An0+wGt+EzgP
wxqz1WNw5baZuNjVEcV4k56xNt25LL4IX7K3KFljBGuII5qS0ESJid94qgKU
rHfcfTyiNMTg6SYBbBsz52RYxgcG65EkVlkYEiQTDaL7OQ/A0244ubLn9kP5
sUijCY5CgaDU1WgXcMtjDobODN7LN5+3e/0VR/3ecre5AIVFVXu3hMJMZVHT
iVnHuZpwEFQ1uBnPKZ+4rWXWXRqNVSDCdzOzpa9YUDr8q+4ox8eixfMbeM6u
4K8xMW0QObau4de+lp/ctmd0Uaxx5TJWQuo1pio/kVBR5w9oIhdksM5yke7S
s8BEFrvb/o05ViK97ToZQUPnvM1nxsQnvDWTpQFbdjlob12f+2EDJDs3liLC
lgNuZUQz1o3f79sjAYMsCb9heE3A23DOXSu40auUhL8ffLpMUy2AOC53CO0N
z2HrccBQ+wyE+MpGOM9DL690vbUa/7ZS5BQs1nlcUo5dSc293Sby+i5G5Yxw
4i4vf4XGJAaY53QPmT3zfMJhdgRK8MBTiAh+nZoGnYtzkvFEvBVxqpSzljlf
uxSvVUMMZ72NcPTSjwKVJteyKzs1fBcwAMW0/Y+SkhQFU5UJC89xk+NIwwKE
Q+rFBWawm7vowpT6h2LeKCf1E9OeWpbuOXRtAbPWGQoVBOBVnWElFJFfz6XZ
sYJuLW1BPQK/oWAEbCg6

TEXT;
        // }}}

        mkdir(self::HOMEDIR);

        $pubring = fopen(self::HOMEDIR . '/pubring.gpg', 'wb');
        fwrite($pubring, base64_decode(str_replace("\n", '', $pubring_data)));
        fclose($pubring);

        $secring = fopen(self::HOMEDIR . '/secring.gpg', 'wb');
        fwrite($secring, base64_decode(str_replace("\n", '', $secring_data)));
        fclose($secring);

        $trustdb = fopen(self::HOMEDIR . '/trustdb.gpg', 'wb');
        fwrite($trustdb, base64_decode(str_replace("\n", '', $trustdb_data)));
        fclose($trustdb);

        $random_seed = fopen(self::HOMEDIR . '/random_seed', 'wb');
        fwrite($random_seed, base64_decode(
            str_replace("\n", '', $random_seed_data)));

        fclose($random_seed);

        $this->_gpg = Crypt_GPG::factory('php',
            array('homedir' => self::HOMEDIR));
    }

    // }}}
    // {{{ tearDown()

    public function tearDown()
    {
        unset($this->_gpg);

        if (file_exists(self::HOMEDIR . '/pubring.gpg~')) {
            unlink(self::HOMEDIR . '/pubring.gpg~');
        }

        if (file_exists(self::HOMEDIR . '/secring.gpg~')) {
            unlink(self::HOMEDIR . '/secring.gpg~');
        }

        if (file_exists(self::HOMEDIR . '/trustdb.gpg~')) {
            unlink(self::HOMEDIR . '/trustdb.gpg~');
        }

        unlink(self::HOMEDIR . '/pubring.gpg');
        unlink(self::HOMEDIR . '/secring.gpg');
        unlink(self::HOMEDIR . '/trustdb.gpg');
        unlink(self::HOMEDIR . '/random_seed');
        rmdir(self::HOMEDIR);
    }

    // }}}

    // tests
    // {{{ testImportKeyPrivateKey()

    public function testImportKeyPrivateKey()
    {
        $expected_result = array(
            'fingerprint'       => 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4',
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        // {{{ private key data
        $private_key_data = <<<TEXT
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

        $result =  $this->_gpg->importKey($private_key_data);
        $this->assertEquals($expected_result, $result);
    }

    // }}}
    // {{{ testImportKeyPublicKey()

    public function testImportKeyPublicKey()
    {
        $expected_result = array(
            'fingerprint'       => '0E8920DF5E2F5FD15A3BC3F14636F589A551E85A',
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        // {{{ public key data
        $public_key_data = <<<TEXT
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

        $result = $this->_gpg->importKey($public_key_data);
        $this->assertEquals($expected_result, $result);
    }

    // }}}
    // {{{ testImportKeyPublicKeyAlreadyImported()

    public function testImportKeyPublicKeyAlreadyImported()
    {
        // {{{ public key data
        $public_key_data = <<<TEXT
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

        $result = $this->_gpg->importKey($public_key_data);

        $expected_result = array(
            'fingerprint'       => '0E8920DF5E2F5FD15A3BC3F14636F589A551E85A',
            'public_imported'   => 1,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expected_result, $result);

        $result = $this->_gpg->importKey($public_key_data);

        $expected_result = array(
            'fingerprint'       => '0E8920DF5E2F5FD15A3BC3F14636F589A551E85A',
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 0,
            'private_unchanged' => 0
        );

        $this->assertEquals($expected_result, $result);
    }

    // }}}
    // {{{ testImportKeyPrivateKeyAlreadyImported()

    public function testImportKeyPrivateKeyAlreadyImported()
    {
        // {{{ private key data
        $private_key_data = <<<TEXT
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

        $result = $this->_gpg->importKey($private_key_data);

        $expected_result = array(
            'fingerprint'       => 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4',
            'public_imported'   => 0,
            'public_unchanged'  => 1,
            'private_imported'  => 1,
            'private_unchanged' => 0
        );

        $this->assertEquals($expected_result, $result);

        $result = $this->_gpg->importKey($private_key_data);

        $expected_result = array(
            'fingerprint'       => 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4',
            'public_imported'   => 0,
            'public_unchanged'  => 0,
            'private_imported'  => 0,
            'private_unchanged' => 1
        );

        $this->assertEquals($expected_result, $result);
    }

    // }}}
    // {{{ testImportKeyNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException()
     */
    public function testImportKeyNoDataException()
    {
        $key_data = 'Invalid OpenPGP data.';
        $this->_gpg->importKey($key_data);
    }

    // }}}
    // {{{ testExportPublicKey()

    public function testExportPublicKey()
    {
        $key_id = 'public-only@example.com';

        // {{{ expected key data
        $expected_key_data = <<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

mQGiBEeQxv0RBAD+cWerD9h+b135x1/m5NWuwpUNpkE7Be4X8PxpwuAHDN2B2QK4
fGF1XWP70RMcvKNx7xR/fbQ25jaHuWPxrxolUADJJwwUqpRZq/ObGo3NWhldVsm2
iU5M2KMwc6D5XQICObyOe9WUJ7HNGKNPclNQzFyhaOA0JcQN+mTlnfwfGwCg2vuY
PzLDcmnyQCdggKLZDy4uARsEALmZFCQQ4SIvLR7IXI+GzhsRkMcNZdqUPLjPhCgl
Fsfigt+o8AGG7wqmkSnqyf+387RYaUB1b7FAZBecYLjnHPC1JCaZ9QZpklibCN9G
3Mii2jF3nogX+OsCJK0q0MFTBjxp1xkqeBoERf9ZUMEw+/j9oCbETTUjzKtTH/MU
YHH/BADKIsdTvwrmkoMXaRIpzGT8UjHwcb8Ao1DrqWxXtaGmf7IJaMiS5bHu2Mv4
0B76G3nEqz6vtSCDsMKH8W5VwDLxnqRe4Tz23gkaKA0fR3PtJw8iuMwGREgEssEM
IJ+Ox7Lc6anHrMqmEafTgsszuO7Y6KMgJ9W6yz+D68OIFlDimbRcUHVibGljIE9u
bHkgVGVzdCBLZXkgKGRvIG5vdCBlbmNyeXB0IGltcG9ydGFudCBkYXRhIHdpdGgg
dGhpcyBrZXkpIDxwdWJsaWMtb25seUBleGFtcGxlLmNvbT6IYAQTEQIAIAUCR5DG
/QIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEBbSdFixu6HEKq8An2DtKGLV
qZ8dzP5MQRq/qw8Zc38eAKCa4g5Z5qckRTm5GunPDPMw54P/5bkCDQRHkMcGEAgA
ok+tFuvdGK4HHDKGDHCy7VSUNGibyy04YFOdOHyx+dojOVroeCeKIgWhOGIEFGpf
mHf3PwUvD0MD91Co1kifTm0LMvUSFNgqW2/5wgfzgmKNvqQbxwHuVAzwKdqxJJRD
WNusQAif8Ch8q8jTeGmCJJM84xZoduaMKz/wKP2XAgKf701CC9nh0XJzaB6Nc8CO
6lBMRf/wzKcGFPy0wiTiuwIC9vSt4yfkwmz0SgndTJtIJjBrTRSF+gEtkjECIO7U
1mCUnjcnn/vm60Ij1r/xlttfkkeML/Hmlj2HNQ8sk2qFqRpf3oVggovyYt6/Xm2/
j0iIQm5aQ3793sb1DfXrSwADBgf9G5D9rUdOQauoCxK0oXPpqbohC3vLpiEzN2qE
jqdt5NVQB/vsPG/4Dzt0Jr5gcRt6DzJ9rDvNY6saTmv1T2LSTm4a6mDoZk2+LGl0
qWCiMvkKlyLTXR61LGIypX2175yzkDEs9KfY+pExZBd/WnkN3xrhTXWgY/i5Ul4C
pU6sE5Kx4cGvioNDE80tMnAI/5mg1Q++fPs8w0Nh1ZGDPHVkyNJpureBWVkMDQ5z
Ln89UMm7wMeNBCNksvt5m5+JzA0t70Dp87khJtbfjADd3MlfX/Fu3w1kfIM6C9j+
xfyAdk/UtMEmEJiYOLziamHI90TZdHXQgV+/b8BLjgYACGQG6IhJBBgRAgAJBQJH
kMcGAhsMAAoJEBbSdFixu6HEzk4AnRNmFvR/Ng19It48QyQO5J1FDmsBAKCRk9xG
y3QoEP81yikT6GomYuIiWA==
=ntky
-----END PGP PUBLIC KEY BLOCK-----

TEXT;
        // }}}

        $key_data = $this->_gpg->exportPublicKey($key_id);
        $this->assertEquals($expected_key_data, $key_data);
    }

    // }}}
    // {{{ testExportPublicKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     */
    public function testExportPublicKeyNotFoundException()
    {
        $key_id = 'non-existent-key@example.com';
        $key_data = $this->_gpg->exportPublicKey($key_id);
    }

    // }}}
    // {{{ testEncrypt()

    public function testEncrypt()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'public-and-private@example.com';
        $passphrase = 'test';

        $encrypted_data = $this->_gpg->encrypt($key_id, $data);
        $decrypted_data = $this->_gpg->decrypt($encrypted_data, $passphrase);

        $this->assertEquals($data, $decrypted_data);
    }

    // }}}
    // {{{ testEncryptKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     */
    public function testEncryptNotFoundException()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'non-existent-key@example.com';
        $encrypted_data = $this->_gpg->encrypt($key_id, $data);
    }

    // }}}
    // {{{ testDecrypt()

    public function testDecrypt()
    {
        $passphrase = 'test';
        $expected_decrypted_data = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with public-and-private@example.com
        // {{{ encrypted data

        $encrypted_data = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA+vrH5iVlTSHEAf/ZKbRk/RXorbxw14OiNABW3+HxrJTDxSqtUZwFWhn9Twr
6nRW+p1T++8h782L/5cIUlPGEZAue0+27qqYnMdkK7R4scbx7euVkT67J/2lajtq
GxjrCZsuhYWzpAQ/EeUYMAK5eqnBXmbrRHjKuAse4O+E4MFtyFyKyck8eeG7e/ia
WDMf/LPb+2MLrR489KMiPo9Mf0g+AZVCC6XluOGdpFx5KxtxvzFbXQ94W1cXKdJH
csBo7SAeHaz/jEkrc7vyYHylcTRYjV1qT6vKkUqxNmMuBryjqTLSBBvGQe4wgOEY
makR0JCC091BjjnAGDvWxwwSduleLCRinmoRKcBnRQgAjTbfak/CpnP+iNl0YDHd
OV8F6GrAjEKTCn+v+vF1pnxETk9wVnjvtCAVrpkgDsxlj80t5DWTr4m1JE71kmpS
LviZWs0Y3obSO88jJZDrVXM7V1lZqIOeTcrK1cKR9QFVqWCiZ0T01uN5+KcZdl1F
vCOIw00P1Aled1FphI+p133CQZM+i2oBCroZUFqvMwrTXKJtchwVzfgAKBDL//PJ
Q4AvPBS+tiFAQyd8AljnvV2SfQzzO4MRvyBU0v4HH0tyLDYbctxw3TQCnlLDc9x8
7g6pKYQEEz4E4vFFXrbyGLwUmBXj0V0X8lNKkNeWLDXT9LEzdEdIhSwGJYQI7o4/
q9JWAWmqMyoBTu1foq42AIz+Qrm/IURnX/Jo+tqSxV1VDB1omuViBugVfS5Joj9K
DVwDqUg1J7qphaE1J7B4HvOKWS/OPcp6/g1cqc0rJde6mpVsq/rorxk=
=dlPv
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $decrypted_data = $this->_gpg->decrypt($encrypted_data, $passphrase);
        $this->assertEquals($expected_decrypted_data, $decrypted_data);
    }

    // }}}
    // {{{ testDecryptNoPassphrase()

    public function testDecryptNoPassphrase()
    {
        $expected_decrypted_data = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with no-passphrase@example.com
        // {{{ encrypted data

        $encrypted_data = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA8ixtjl4qXlLEAgAsKt+cWqkj6IOyceF9OwOD+4basLSnqIYabeWwZoGycdY
Q79gBo/wXTdxJ27fdFQM7an0e2cOrTl96xgVbRn1tDbBYjRBUFkQKWrWMP9P6bZ3
4eZDewdwFzda6kjTN6OAo/LtzFborespoLl0oqm8MX1Z+Uo9V2gyOd5O+HEAx40y
ylgsTVIC9pJzGqTd7nZ3Q5y/mQrgfGt3W7WLB47Zh4Nqp8epj48xrYUFxdIZrZb8
8e5kL4Gbn5Y2AXaKUw3LhnqKgDidiXbg6R0LAMX5SgP2QLwKMKdumx5Pbm5cX6hL
zR853+7YRXomeM1YqaxGn014xe+V8wMVXLGk0m7aHgf+PKVi2su94wHsUdj2yXdD
egQaTICoLTJDe17qvMIQhjyg9gLfCgir8iB54fHtHNcSMOJvi8n30OflC0jRdw40
OmXXf1Hrfg/TH/adpUP7nTOpQ6sllVVEVSFhfFRPmem6sGBiz3lJRA5Vq2S3Ev0V
OLuXhNIjcKrWzIFgtYI3YBYylW1dDujIguT8yU4IwTG5wI54vTzWl9lZ9h5OkKMy
IzPZaG5F9i6pdo/RZG5R7OJAOn+AtYSPWMQXorIRSkW0e62QJDUDViYXUdHa0TDP
RI9hBISs8omyhtVwnArR0CR2+BBUZWKjqgbY34+Lx/CrsB32lA0o2QN9UzaEHc7m
39JWAYygjsGHOGIT8Rwy9eV2DNPtJlJXc+Me0ERYXeL/xn972+Vp7hnLog2n4Twt
FEt7GdVwA0ryp3/f0V4E3JylrLdTHF1aQ7VwzPoRPH8i5b7znucreD0=
=sOP6
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $decrypted_data = $this->_gpg->decrypt($encrypted_data);
        $this->assertEquals($expected_decrypted_data, $decrypted_data);
    }

    // }}}
    // {{{ testDecryptKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     */
    public function testDecryptKeyNotFoundException()
    {
        $passphrase = 'test';

        // was encrypted with test@example.com
        // {{{ encrypted data

        $encrypted_data = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA9iRsCBTswBBEAgA48W4igBuoGyFW9IMrWl7CEfUKwC/rRXJbK1MbESlHsA0
CVG1c1Y/vLYOXVgPeuHokwwTau0nmpKIOCxMUymBu8N66UK+8RvAPekoCLlKjNg0
iOVPu+62bPvVWHgKvWM4Kj2MKXGhC1m4OaHonaDffVMTmsa4ndEUoOV9TQb/nBNt
L7JZ+N/KXie9nIoqJgvA1Gb0zuMkFUsLaJ+e3HThRyQUyzZ7k5LLBOTgEKW3urtK
m9lOPTyqOCKEsNflT3XI3823do3EF//damROGNLtMcI92vQA2cY/X3reoJjN5Nb+
yLOVkSjVGxJIXE2tPtKwJC6dELy2xTCPL0aagliqiQgAzB6/NLfos89XD4y3cvcq
a8pfdKwGd9fsUGFtntd8Jf8moWOkLJbh1vRUyxn5eSJKHiu52FjrOCSQOWLax/qZ
RHQM1h1MK6isLHysLgq6naLUyJVXmpL9HSrUYaCP4+jefNeC2nRAonYAr18nfAHF
1AiRzDE3+MDy8vRZLWOitsrhqYDrCyg+x7qvgLjK5F5SSc8ZwyE3Rlee+NbRjXH3
fzAE/l6P9GlZrZUL5inEUDBm+DB/LQcnB9K32XD/7Lkeh92Ih6d/Ykbctc0bzuD4
CnkU/rA4z5e8s81CopOW65FchxkLK8YFGf623IURbrga7sVW0wj13AbLcmVO5fiS
xNJWASwiaUHH6Lll3gHdcJJlMW9THKzOk2UzV56t4ZaqJPrYwWMONHS60P+UVtl2
HQpCFn/UK5EjrXyd9DHdYHGRL2n8O3xjhu1GVuuA4sb3B46nKzxXzcU=
=q3cD
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $decrypted_data = $this->_gpg->decrypt($encrypted_data, $passphrase);
    }

    // }}}
    // {{{ testDecryptNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     */
    public function testDecryptNoDataException()
    {
        $passphrase = 'test';
        $encrypted_data = 'Invalid OpenPGP data.';
        $decrypted_data = $this->_gpg->decrypt($encrypted_data, $passphrase);
    }

    // }}}
    // {{{ testDecryptBadPassphraseException_missing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     */
    public function testDecryptBadPassphraseException_missing()
    {
        // encrypted with public-and-private@example.com
        // {{{ encrypted data

        $encrypted_data = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA+vrH5iVlTSHEAf/ZKbRk/RXorbxw14OiNABW3+HxrJTDxSqtUZwFWhn9Twr
6nRW+p1T++8h782L/5cIUlPGEZAue0+27qqYnMdkK7R4scbx7euVkT67J/2lajtq
GxjrCZsuhYWzpAQ/EeUYMAK5eqnBXmbrRHjKuAse4O+E4MFtyFyKyck8eeG7e/ia
WDMf/LPb+2MLrR489KMiPo9Mf0g+AZVCC6XluOGdpFx5KxtxvzFbXQ94W1cXKdJH
csBo7SAeHaz/jEkrc7vyYHylcTRYjV1qT6vKkUqxNmMuBryjqTLSBBvGQe4wgOEY
makR0JCC091BjjnAGDvWxwwSduleLCRinmoRKcBnRQgAjTbfak/CpnP+iNl0YDHd
OV8F6GrAjEKTCn+v+vF1pnxETk9wVnjvtCAVrpkgDsxlj80t5DWTr4m1JE71kmpS
LviZWs0Y3obSO88jJZDrVXM7V1lZqIOeTcrK1cKR9QFVqWCiZ0T01uN5+KcZdl1F
vCOIw00P1Aled1FphI+p133CQZM+i2oBCroZUFqvMwrTXKJtchwVzfgAKBDL//PJ
Q4AvPBS+tiFAQyd8AljnvV2SfQzzO4MRvyBU0v4HH0tyLDYbctxw3TQCnlLDc9x8
7g6pKYQEEz4E4vFFXrbyGLwUmBXj0V0X8lNKkNeWLDXT9LEzdEdIhSwGJYQI7o4/
q9JWAWmqMyoBTu1foq42AIz+Qrm/IURnX/Jo+tqSxV1VDB1omuViBugVfS5Joj9K
DVwDqUg1J7qphaE1J7B4HvOKWS/OPcp6/g1cqc0rJde6mpVsq/rorxk=
=dlPv
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $decrypted_data = $this->_gpg->decrypt($encrypted_data);
    }

    // }}}
    // {{{ testDecryptBadPassphraseException_bad()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     */
    public function testDecryptBadPassphraseException_bad()
    {
        $passphrase = 'incorrect';

        // encrypted with public-and-private@example.com
        // {{{ encrypted data

        $encrypted_data = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA+vrH5iVlTSHEAf/ZKbRk/RXorbxw14OiNABW3+HxrJTDxSqtUZwFWhn9Twr
6nRW+p1T++8h782L/5cIUlPGEZAue0+27qqYnMdkK7R4scbx7euVkT67J/2lajtq
GxjrCZsuhYWzpAQ/EeUYMAK5eqnBXmbrRHjKuAse4O+E4MFtyFyKyck8eeG7e/ia
WDMf/LPb+2MLrR489KMiPo9Mf0g+AZVCC6XluOGdpFx5KxtxvzFbXQ94W1cXKdJH
csBo7SAeHaz/jEkrc7vyYHylcTRYjV1qT6vKkUqxNmMuBryjqTLSBBvGQe4wgOEY
makR0JCC091BjjnAGDvWxwwSduleLCRinmoRKcBnRQgAjTbfak/CpnP+iNl0YDHd
OV8F6GrAjEKTCn+v+vF1pnxETk9wVnjvtCAVrpkgDsxlj80t5DWTr4m1JE71kmpS
LviZWs0Y3obSO88jJZDrVXM7V1lZqIOeTcrK1cKR9QFVqWCiZ0T01uN5+KcZdl1F
vCOIw00P1Aled1FphI+p133CQZM+i2oBCroZUFqvMwrTXKJtchwVzfgAKBDL//PJ
Q4AvPBS+tiFAQyd8AljnvV2SfQzzO4MRvyBU0v4HH0tyLDYbctxw3TQCnlLDc9x8
7g6pKYQEEz4E4vFFXrbyGLwUmBXj0V0X8lNKkNeWLDXT9LEzdEdIhSwGJYQI7o4/
q9JWAWmqMyoBTu1foq42AIz+Qrm/IURnX/Jo+tqSxV1VDB1omuViBugVfS5Joj9K
DVwDqUg1J7qphaE1J7B4HvOKWS/OPcp6/g1cqc0rJde6mpVsq/rorxk=
=dlPv
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $decrypted_data = $this->_gpg->decrypt($encrypted_data, $passphrase);
    }

    // }}}
    // {{{ testDeletePublicKey()

    public function testDeletePublicKey()
    {
        $key_id = 'public-only@example.com';
        $this->_gpg->deletePublicKey($key_id);

        $expected_keys = array();
        $keys = $this->_gpg->getKeys($key_id);
        $this->assertEquals($expected_keys, $keys);
    }

    // }}}
    // {{{ testDeletePublicKeyDeletePrivateKeyException()

    /**
     * @expectedException Crypt_GPG_DeletePrivateKeyException
     */
    public function testDeletePublicKeyDeletePrivateKeyException()
    {
        $key_id = 'public-and-private@example.com';
        $this->_gpg->deletePublicKey($key_id);
    }

    // }}}
    // {{{ testDeletePublicKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     */
    public function testDeletePublicKeyNotFoundException()
    {
        $key_id = 'non-existent-key@example.com';
        $this->_gpg->deletePublicKey($key_id);
    }

    // }}}
    // {{{ testDeletePrivateKey()

    public function testDeletePrivateKey()
    {
        $key_id = 'public-and-private@example.com';
        $this->_gpg->deletePrivateKey($key_id);

        $expected_keys = array();

        // {{{ public-and-private@example.com
        $key = new Crypt_GPG_Key();
        $expected_keys[] = $key;

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('Public and Private Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('public-and-private@example.com');
        $key->addUserId($user_id);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('300579D099645239');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $sub_key->setFingerprint('5A58436F752BC80B3E992C1D300579D099645239');
        $sub_key->setLength(1024);
        $sub_key->setCreationDate(1200670392);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(true);
        $sub_key->setCanEncrypt(false);
        $sub_key->setHasPrivate(false);
        $key->addSubKey($sub_key);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('EBEB1F9895953487');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $sub_key->setFingerprint('DCC9E7AAB9248CB0541FADDAEBEB1F9895953487');
        $sub_key->setLength(2048);
        $sub_key->setCreationDate(1200670397);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(false);
        $sub_key->setCanEncrypt(true);
        $sub_key->setHasPrivate(false);
        $key->addSubKey($sub_key);
        // }}}

        $keys = $this->_gpg->getKeys($key_id);
        $this->assertEquals($expected_keys, $keys);
    }

    // }}}
    // {{{ testDeletePrivateKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     */
    public function testDeletePrivateKeyNotFoundException()
    {
        $key_id = 'non-existent-key@example.com';
        $this->_gpg->deletePrivateKey($key_id);
    }

    // }}}
    // {{{ testDeletePrivateKeyNotFoundException_public_only()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     */
    public function testDeletePrivateKeyNotFoundException_public_only()
    {
        $key_id = 'public-only@example.com';
        $this->_gpg->deletePrivateKey($key_id);
    }

    // }}}
    // {{{ testSignKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     */
    public function testSignKeyNotFoundException()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'non-existent-key@example.com';
        $signed_data = $this->_gpg->sign($key_id, $data);
    }

    // }}}
    // {{{ testSignBadPassphraseException_missing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     */
    public function testSignBadPassphraseException_missing()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'public-and-private@example.com';
        $signed_data = $this->_gpg->sign($key_id, $data);
    }

    // }}}
    // {{{ testSignBadPassphraseException_bad()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     */
    public function testSignBadPassphraseException_bad()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'public-and-private@example.com';
        $passphrase = 'incorrect';
        $signed_data = $this->_gpg->sign($key_id, $data, $passphrase);
    }

    // }}}
    // {{{ testSignNoPassphrase()

    public function testSignNoPassphrase()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'no-passphrase@example.com';
        $signed_data = $this->_gpg->sign($key_id, $data);

        $signature = $this->_gpg->verify($signed_data);
        $this->assertTrue($signature->isValid());
    }

    // }}}
    // {{{ testSignNormal()

    public function testSignNormal()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'public-and-private@example.com';
        $passphrase = 'test';
        $signed_data = $this->_gpg->sign($key_id, $data, $passphrase);

        $signature = $this->_gpg->verify($signed_data);
        $this->assertTrue($signature->isValid());
    }

    // }}}
    // {{{ testSignClear()

    public function testSignClear()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'public-and-private@example.com';
        $passphrase = 'test';
        $signed_data = $this->_gpg->sign($key_id, $data, $passphrase,
            Crypt_GPG::SIGN_MODE_CLEAR);

        $signature = $this->_gpg->verify($signed_data);
        $this->assertTrue($signature->isValid());
    }

    // }}}
    // {{{ testSignDetached()

    public function testSignDetached()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'public-and-private@example.com';
        $passphrase = 'test';
        $signature_data = $this->_gpg->sign($key_id, $data, $passphrase,
            Crypt_GPG::SIGN_MODE_DETACHED);

        $signature = $this->_gpg->verify($data, $signature_data);
        $this->assertTrue($signature->isValid());
    }

    // }}}
    // {{{ testVerifyNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     */
    public function testVerifyNoDataException()
    {
        $signed_data = 'Invalid OpenPGP data.';
        $signature = $this->_gpg->verify($signed_data);
    }

    // }}}
    // {{{ testVerifyNormalSignedData()

    public function testVerifyNormalSignedData()
    {
        // {{{ expected signature
        $expected_signature = new Crypt_GPG_Signature();
        $expected_signature->setId('vQ2mozoe+N5TQhaFsRAJmNHhsB');
        $expected_signature->setKeyFingerprint(
            '5A58436F752BC80B3E992C1D300579D099645239');

        $expected_signature->setCreationDate(1200674360);
        $expected_signature->setExpirationDate(0);
        $expected_signature->setIsValid(true);

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('Public and Private Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('public-and-private@example.com');
        $expected_signature->setUserId($user_id);
        // }}}
        // {{{ normal signed data
        $normal_signed_data = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

owGbwMvMwCRowFp5YWZKkCXjacUkBvcJ1/Q8UnNy8nUUHHMyk1MVFdzz81OSKlN1
FJzykxQ77JlZQWosYJoEmb5fY5ins3He0itLAmPWuUzXWXum+bjCGp8zDAum/7Tm
ZOALdV5uO8dv5ewQ9XOp6bsA
=e7Vg
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $signature = $this->_gpg->verify($normal_signed_data);
        $this->assertEquals($expected_signature, $signature);
    }

    // }}}
    // {{{ testVerifyClearsignedData()

    public function testVerifyClearsignedData()
    {
        // {{{ expected signature
        $expected_signature = new Crypt_GPG_Signature();
        $expected_signature->setId('mvtJs/XKU5KwDQ91YH0efv6vA7');
        $expected_signature->setKeyFingerprint(
            '5A58436F752BC80B3E992C1D300579D099645239');

        $expected_signature->setCreationDate(1200674325);
        $expected_signature->setExpirationDate(0);
        $expected_signature->setIsValid(true);

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('Public and Private Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('public-and-private@example.com');
        $expected_signature->setUserId($user_id);
        // }}}
        // {{{ clearsigned data
        $clearsigned_data = <<<TEXT
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

        $signature = $this->_gpg->verify($clearsigned_data);
        $this->assertEquals($expected_signature, $signature);
    }

    // }}}
    // {{{ testVerifyDetachedSignature()

    public function testVerifyDetachedSignature()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        // {{{ expected signature
        $expected_signature = new Crypt_GPG_Signature();
        $expected_signature->setId('0Wyj4MWXtqzVT6nvgEQ+De2sV6');
        $expected_signature->setKeyFingerprint(
            '5A58436F752BC80B3E992C1D300579D099645239');

        $expected_signature->setCreationDate(1200674279);
        $expected_signature->setExpirationDate(0);
        $expected_signature->setIsValid(true);

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('Public and Private Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('public-and-private@example.com');
        $expected_signature->setUserId($user_id);
        // }}}
        // {{{ detached signature
        $detached_signature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBHkNXnMAV50JlkUjkRAvDnAJ9TViHfxW127Clvh3y/2SmAIvKyfwCfeD/q
aLnxi+7N7THxsFSmpqLPRrQ=
=hawX
-----END PGP SIGNATURE-----

TEXT;

        // }}}

        $signature = $this->_gpg->verify($data, $detached_signature);
        $this->assertEquals($expected_signature, $signature);
    }

    // }}}
    // {{{ testGetKeys()

    public function testGetKeys()
    {
        $expected_keys = array();

        // {{{ public-and-private@example.com
        $key = new Crypt_GPG_Key();
        $expected_keys[] = $key;

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('Public and Private Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('public-and-private@example.com');
        $key->addUserId($user_id);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('300579D099645239');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $sub_key->setFingerprint('5A58436F752BC80B3E992C1D300579D099645239');
        $sub_key->setLength(1024);
        $sub_key->setCreationDate(1200670392);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(true);
        $sub_key->setCanEncrypt(false);
        $sub_key->setHasPrivate(true);
        $key->addSubKey($sub_key);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('EBEB1F9895953487');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $sub_key->setFingerprint('DCC9E7AAB9248CB0541FADDAEBEB1F9895953487');
        $sub_key->setLength(2048);
        $sub_key->setCreationDate(1200670397);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(false);
        $sub_key->setCanEncrypt(true);
        $sub_key->setHasPrivate(true);
        $key->addSubKey($sub_key);
        // }}}
        // {{{ public-only@example.com
        $key = new Crypt_GPG_Key();
        $expected_keys[] = $key;

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('Public Only Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('public-only@example.com');
        $key->addUserId($user_id);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('16D27458B1BBA1C4');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $sub_key->setFingerprint('C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4');
        $sub_key->setLength(1024);
        $sub_key->setCreationDate(1200670461);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(true);
        $sub_key->setCanEncrypt(false);
        $sub_key->setHasPrivate(false);
        $key->addSubKey($sub_key);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('045B7FC31C7C4644');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $sub_key->setFingerprint('0DC192B106773BC9B4D40AAC045B7FC31C7C4644');
        $sub_key->setLength(2048);
        $sub_key->setCreationDate(1200670470);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(false);
        $sub_key->setCanEncrypt(true);
        $sub_key->setHasPrivate(false);
        $key->addSubKey($sub_key);
        // }}}
        // {{{ no-passphrase@example.com
        $key = new Crypt_GPG_Key();
        $expected_keys[] = $key;

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('No Passphrase Public and Private Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('no-passphrase@example.com');
        $key->addUserId($user_id);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('CB24072FEF665D17');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $sub_key->setFingerprint('D729E804DD50012902232845CB24072FEF665D17');
        $sub_key->setLength(1024);
        $sub_key->setCreationDate(1200671161);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(true);
        $sub_key->setCanEncrypt(false);
        $sub_key->setHasPrivate(true);
        $key->addSubKey($sub_key);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('C8B1B63978A9794B');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $sub_key->setFingerprint('1BB64D19DFC5DC1AFAB79C63C8B1B63978A9794B');
        $sub_key->setLength(2048);
        $sub_key->setCreationDate(1200671172);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(false);
        $sub_key->setCanEncrypt(true);
        $sub_key->setHasPrivate(true);
        $key->addSubKey($sub_key);
        // }}}

        $keys = $this->_gpg->getKeys();
        $this->assertEquals($expected_keys, $keys);
    }

    // }}}
    // {{{ testGetKeysWithKeyId()

    public function testGetKeysWithKeyId()
    {
        $key_id = 'public-and-private@example.com';
        $expected_keys = array();

        // {{{ public-and-private@example.com
        $key = new Crypt_GPG_Key();
        $expected_keys[] = $key;

        $user_id = new Crypt_GPG_UserId();
        $user_id->setName('Public and Private Test Key');
        $user_id->setComment('do not encrypt important data with this key');
        $user_id->setEmail('public-and-private@example.com');
        $key->addUserId($user_id);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('300579D099645239');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_DSA);
        $sub_key->setFingerprint('5A58436F752BC80B3E992C1D300579D099645239');
        $sub_key->setLength(1024);
        $sub_key->setCreationDate(1200670392);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(true);
        $sub_key->setCanEncrypt(false);
        $sub_key->setHasPrivate(true);
        $key->addSubKey($sub_key);

        $sub_key = new Crypt_GPG_SubKey();
        $sub_key->setId('EBEB1F9895953487');
        $sub_key->setAlgorithm(Crypt_GPG_SubKey::ALGORITHM_ELGAMAL_ENC);
        $sub_key->setFingerprint('DCC9E7AAB9248CB0541FADDAEBEB1F9895953487');
        $sub_key->setLength(2048);
        $sub_key->setCreationDate(1200670397);
        $sub_key->setExpirationDate(0);
        $sub_key->setCanSign(false);
        $sub_key->setCanEncrypt(true);
        $sub_key->setHasPrivate(true);
        $key->addSubKey($sub_key);
        // }}}

        $keys = $this->_gpg->getKeys($key_id);
        $this->assertEquals($expected_keys, $keys);
    }

    // }}}
    // {{{ testGetKeysNone()

    public function testGetKeysNone()
    {
        $key_id = 'non-existent-key@example.com';
        $expected_keys = array();
        $keys = $this->_gpg->getKeys($key_id);
        $this->assertEquals($expected_keys, $keys);
    }

    // }}}
    // {{{ testGetFingerprint()

    public function testGetFingerprint()
    {
        $key_id = 'public-only@example.com';
        $expected_fingerprint = 'C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4';
        $fingerprint = $this->_gpg->getFingerprint($key_id);
        $this->assertEquals($expected_fingerprint, $fingerprint);
    }

    // }}}
    // {{{ testGetFingerprintNull()

    public function testGetFingerprintNull()
    {
        $key_id = 'non-existent-key@example.com';
        $fingerprint = $this->_gpg->getFingerprint($key_id);
        $this->assertNull($fingerprint);
    }

    // }}}
    // {{{ testGetFingerprintX509()

    public function testGetFingerprintX509()
    {
        $key_id = 'public-only@example.com';
        $expected_fingerprint =
            'C3:BC:61:5A:D9:C7:66:E5:A8:5C:1F:27:16:D2:74:58:B1:BB:A1:C4';

        $fingerprint = $this->_gpg->getFingerprint($key_id,
            Crypt_GPG::FORMAT_X509);

        $this->assertEquals($expected_fingerprint, $fingerprint);
    }

    // }}}
    // {{{ testGetFingerprintCanonical()

    public function testGetFingerprintCanonical()
    {
        $key_id = 'public-only@example.com';
        $expected_fingerprint =
            'C3BC 615A D9C7 66E5 A85C  1F27 16D2 7458 B1BB A1C4';

        $fingerprint = $this->_gpg->getFingerprint($key_id,
            Crypt_GPG::FORMAT_CANONICAL);

        $this->assertEquals($expected_fingerprint, $fingerprint);
    }

    // }}}
}

?>
