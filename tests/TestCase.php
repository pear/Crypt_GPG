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
 * PHPUnit3 framework
 */
require_once 'PHPUnit/Framework.php';

/**
 * The Crypt_GPG class to test
 */
require_once 'Crypt/GPG.php';

/**
 * Key class definition
 */
require_once 'Crypt/GPG/Key.php';

/**
 * Signature class definition
 */
require_once 'Crypt/GPG/Signature.php';

/**
 * Abstract base class for testing Crypt_GPG.
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
abstract class TestCase extends PHPUnit_Framework_TestCase
{
    // {{{ class constants

    const HOMEDIR = './test-keychain';

    // }}}
    // {{{ protected properties

    protected $gpg;

    // }}}
    // {{{ private properties

    private $_old_error_level;

    // }}}
    // {{{ setUp()

    public function setUp()
    {
        $this->_old_error_level = error_reporting(E_ALL | E_STRICT);

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

        $this->gpg = new Crypt_GPG($this->getOptions());
    }

    // }}}
    // {{{ tearDown()

    public function tearDown()
    {
        unset($this->gpg);

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

        // remove temporary process id files used by gpgme
        $iterator = new DirectoryIterator(self::HOMEDIR);
        foreach ($iterator as $file) {
            if (strncmp($file->getFilename(), '.#', 2) == 0) {
                unlink(self::HOMEDIR . '/' . $file->getFilename());
            }
        }

        rmdir(self::HOMEDIR);

        error_reporting($this->_old_error_level);
    }

    // }}}
    // {{{ getOptions()

    protected function getOptions()
    {
        return array(
            'homedir' => self::HOMEDIR,
//            'debug'   => true
        );
    }

    // }}}
}

?>
