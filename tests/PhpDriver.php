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
 * @todo Aassert delete tests worked.
 * @todo Assert sign tests worked.
 * @todo Assert verify tests worked.
 * @todo Assert get public/private keys worked.
 * @todo Add tests for Exception API.
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
mQGiBEeJvQURBACX8TxSFbEL2q2utva0lpr1XDesb8rghTOK2+nUSlB4CwIT
npJW9iRsS1FRGDgOjlde8qnjttvhT0/pAv7iEQvyHhfwSZ9LvnElgJQM29OO
azxeRanhbfMh5Qqu7bzFZ+3gg4OJj2mSpGvVYfgAzArl+Fg9pN7gnrtKZcgd
sb0xqwCg4uW0yAhyCreu3futN5nWyuuEYPsEAIEJbO7ICx587TUgjf06CfMQ
PCpGDbn6m/ZF8ufihhSN+lcBoJwOUNJvwfIfXQJS6fJv/Cc+DWaRROdb/fEf
Ge23tLAqHC7ouuAhX5AoNbAyJNLiUjShVJS8N4eu1YvusaceveBplP9JnY/M
NeZCewgKXgBr5XFWEDCVJHpW6S3RA/0X5Rwxgjq+KQ27upl3674aBlC0Nso8
yjPmFcbWK67WTlti1NZZh5CcKb7knIlNWfQkaFSXBjdH3mkUTYWKbuqKLL7T
A6L1p+IHIHW/azxq/RssyTh8DVudBWTcEuc97jLl7OuKvG0UcYkBKRQrKAJf
tdNkopCG/Fk1Qp+Wu+5esrRQR1BHIFRlc3QgVXNlciAoRG8gbm90IGVuY3J5
cHQgc2Vuc2l0aXZlIGRhdGEgdXNpbmcgdGhpcyBrZXkuKSA8dGVzdEBleGFt
cGxlLmNvbT6IYAQTEQIAIAUCR4m9BQIbAwYLCQgHAwIEFQIIAwQWAgMBAh4B
AheAAAoJEDxD7ATuGLNmQgIAoMBbT1bF5xyI414s9F802219JY6uAJ0dvIdr
+Xs4kVLx1xZhGWeZsrwewrACAAO5Ag0ER4m9DxAIAPGfdpUGnucnr6SnDS7B
zuBcBcLG7+5PGHvTcaCzBFyPfrTatb9Xr+1fDq5Xp2BgGSp8rOmSIWGj81CZ
vXuHDzuvDeYIPZCP9eGtRSYCwi/O83WODS9hDuxFvVn22RIi+1jZB2cRgri+
+4kjisJMBloCsRUcJSm7VP1D+8+PBhLjn3l2meQjOcj1hjMFq5/PrJqV9+4E
peY+2HKAr0ciOygCUnLtEEQa37nfzQ/UJotXKU6wHIgBmOBLXzj5qeQ9Ujmc
GaC4ti5EzjlS3sH2Wr2APo1xnNydt5zgOkDEkVodSDQb3ENb7kt6ylOJ/vcU
qTrjztPN/Z+peF+4P0ED2eMAAwUIAKchTEQ5gcOfwM5N+Oo6hGrSBRe3jVV2
6KvSDtya9a9TSlyySbeBtk9i2q90JSVuKd04yQFBytgnz9qBAZWpiZxFOQBH
ymXIvXfaYU/s+VzaQSCBWWER9s0QEn7ZtgOQOWYR5gwlqdFlMojWOnOKEAON
cKAgwBD3vJ8yM9ko0ONhJXf3gu7pHbRSDod3O/OS7kO3wpc0S6yPZJlRBbdv
rj4A4qnjN/QLehuwt9amndz3PTFdrJ0t4UvZmxYE+g7pFVeR3kt2jzlYO2dE
wfyV8DiEByAvlRSa2o/qK0g2fNDnlMqh6fVgKFL/QzzB+PsMHfG5T9X6z3+F
yk3mI10VyYmISQQYEQIACQUCR4m9DwIbDAAKCRA8Q+wE7hizZtQmAJ9gW34g
Etdnnnj/T6LkZZBbm/p3pwCeLOBF9drMQKLg8xUtnEydL0RVLWSwAgAD

TEXT;
        // }}}
        // {{{ secring data
        $secring_data = <<<TEXT
lQHhBEeJvQURBACX8TxSFbEL2q2utva0lpr1XDesb8rghTOK2+nUSlB4CwIT
npJW9iRsS1FRGDgOjlde8qnjttvhT0/pAv7iEQvyHhfwSZ9LvnElgJQM29OO
azxeRanhbfMh5Qqu7bzFZ+3gg4OJj2mSpGvVYfgAzArl+Fg9pN7gnrtKZcgd
sb0xqwCg4uW0yAhyCreu3futN5nWyuuEYPsEAIEJbO7ICx587TUgjf06CfMQ
PCpGDbn6m/ZF8ufihhSN+lcBoJwOUNJvwfIfXQJS6fJv/Cc+DWaRROdb/fEf
Ge23tLAqHC7ouuAhX5AoNbAyJNLiUjShVJS8N4eu1YvusaceveBplP9JnY/M
NeZCewgKXgBr5XFWEDCVJHpW6S3RA/0X5Rwxgjq+KQ27upl3674aBlC0Nso8
yjPmFcbWK67WTlti1NZZh5CcKb7knIlNWfQkaFSXBjdH3mkUTYWKbuqKLL7T
A6L1p+IHIHW/azxq/RssyTh8DVudBWTcEuc97jLl7OuKvG0UcYkBKRQrKAJf
tdNkopCG/Fk1Qp+Wu+5esv4DAwKtbw2Rb2gwNGByZskyHBW8UObQ59xmWXn7
o2e/t0n3/C1qQv5PgEKPJOwaFKG9LuHfBjRDTIzAtTFisrRQR1BHIFRlc3Qg
VXNlciAoRG8gbm90IGVuY3J5cHQgc2Vuc2l0aXZlIGRhdGEgdXNpbmcgdGhp
cyBrZXkuKSA8dGVzdEBleGFtcGxlLmNvbT6IYAQTEQIAIAUCR4m9BQIbAwYL
CQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEDxD7ATuGLNmQgIAoMBbT1bF5xyI
414s9F802219JY6uAJ0dvIdr+Xs4kVLx1xZhGWeZsrwewrACAACdAmMER4m9
DxAIAPGfdpUGnucnr6SnDS7BzuBcBcLG7+5PGHvTcaCzBFyPfrTatb9Xr+1f
Dq5Xp2BgGSp8rOmSIWGj81CZvXuHDzuvDeYIPZCP9eGtRSYCwi/O83WODS9h
DuxFvVn22RIi+1jZB2cRgri++4kjisJMBloCsRUcJSm7VP1D+8+PBhLjn3l2
meQjOcj1hjMFq5/PrJqV9+4EpeY+2HKAr0ciOygCUnLtEEQa37nfzQ/UJotX
KU6wHIgBmOBLXzj5qeQ9UjmcGaC4ti5EzjlS3sH2Wr2APo1xnNydt5zgOkDE
kVodSDQb3ENb7kt6ylOJ/vcUqTrjztPN/Z+peF+4P0ED2eMAAwUIAKchTEQ5
gcOfwM5N+Oo6hGrSBRe3jVV26KvSDtya9a9TSlyySbeBtk9i2q90JSVuKd04
yQFBytgnz9qBAZWpiZxFOQBHymXIvXfaYU/s+VzaQSCBWWER9s0QEn7ZtgOQ
OWYR5gwlqdFlMojWOnOKEAONcKAgwBD3vJ8yM9ko0ONhJXf3gu7pHbRSDod3
O/OS7kO3wpc0S6yPZJlRBbdvrj4A4qnjN/QLehuwt9amndz3PTFdrJ0t4UvZ
mxYE+g7pFVeR3kt2jzlYO2dEwfyV8DiEByAvlRSa2o/qK0g2fNDnlMqh6fVg
KFL/QzzB+PsMHfG5T9X6z3+Fyk3mI10VyYn+AwMCrW8NkW9oMDRgmduTMNMU
lsVlOOEOdcqIJ6fkTyiG8RjUjX3GNC6Rm2bfgJKGyLP9s4+GForXdEIch9lO
C62jjBjzMi+kOUyW1O7xgiwi2cQrgIhJBBgRAgAJBQJHib0PAhsMAAoJEDxD
7ATuGLNm1CYAn2BbfiAS12eeeP9PouRlkFub+nenAJ4s4EX12sxAouDzFS2c
TJ0vRFUtZLACAAA=

TEXT;
        // }}}
        // {{{ trustdb data
        $trustdb_data = <<<TEXT
AWdwZwMDAQUBAAAAR4nAbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAB4AAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADABrvPK9dKSoLw3eE5c8
Q+wE7hizZgAAAAAAAAAfAAAAAAAAAAAAAA0AysbMxl08eg2k9oEgzz2Nnf/w
QncAAAAAAAAAAAAAAAAAAAAAAAA=

TEXT;
        // }}}
        // {{{ random_seed data
        $random_seed_data = <<<TEXT
psHHMYiKI5UfHNUp1mQf9oNSGguXQ47Us6ouzC8T/PMMOKSgNbXg+2SnHJWl
sNrDYPiQKxXT7wxM186v7K2Krub0nSKXclSMniBJG1Joo0vcuJOlDS4v5P4X
nSg7yfkSqSCeC4fr+6/2BcJ1aoXAdPjXEIFHOijbvXBxWNoFQGnritsL9VY7
qHcOSd80cYyScvsosYRPDEwXLJL8cfSkqyaONGk5GS1epq2nZqaENdJanrbU
2DoRb4lA8tkGk/hu1pWSg4ZeS8mgb3MBnxNI5109q6nzdpy+edZNK4pBWLd5
TcTaQDyJkqJ9bOPgWuZwaUVMkIlyq/XVwKuRrs/LDb89rmNYbJVd4vdi01s3
4VNSp4DJM3XwL+NjaHWEtxjtnf5i6NjAb36sE4Ryzr0k461/RB7KvRoVFefT
2uTp3zCNYk56ZVy874gl4BwGKD9k1PxXual/+nCcB+ax5rfIQ5xbN59IJSAg
j3WLLSt5vi2K7/DtWdwjd6jgYbzg58nPdReoYjhDK3bcvHHLGB4Y0baadz0X
XmNTCPpwB134j34EwgP3AKEwMYm9+y9u5zhB6Mnes5aM6iB1Ph9S5l2+G/Pw
7+JkIv9IH4T9NHWtPRMEcKs/AXZfm9RwskSBRYIYZNUoXRmMBzgnYEPoDVdS
x8J6tyXP59jNsDLmtkAAHQcLowmD1QVcz3vwPP8eDicx2CLEgE+qMydMRhp6
SO/Sm4lq8rUKBdgj46hAZnM7Q/WHQx8GPw2WrXHrKq+whg+wy5cwfCttZwoK
OARI8C87jU5v17gG9UZz

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
    // {{{ testImportPrivateKey()

    public function testImportPrivateKey()
    {
        $key_id = 'test@example.com';

        // {{{ private key data
        $private_key_data = <<<TEXT
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.6 (GNU/Linux)

lQHhBEeJvQURBACX8TxSFbEL2q2utva0lpr1XDesb8rghTOK2+nUSlB4CwITnpJW
9iRsS1FRGDgOjlde8qnjttvhT0/pAv7iEQvyHhfwSZ9LvnElgJQM29OOazxeRanh
bfMh5Qqu7bzFZ+3gg4OJj2mSpGvVYfgAzArl+Fg9pN7gnrtKZcgdsb0xqwCg4uW0
yAhyCreu3futN5nWyuuEYPsEAIEJbO7ICx587TUgjf06CfMQPCpGDbn6m/ZF8ufi
hhSN+lcBoJwOUNJvwfIfXQJS6fJv/Cc+DWaRROdb/fEfGe23tLAqHC7ouuAhX5Ao
NbAyJNLiUjShVJS8N4eu1YvusaceveBplP9JnY/MNeZCewgKXgBr5XFWEDCVJHpW
6S3RA/0X5Rwxgjq+KQ27upl3674aBlC0Nso8yjPmFcbWK67WTlti1NZZh5CcKb7k
nIlNWfQkaFSXBjdH3mkUTYWKbuqKLL7TA6L1p+IHIHW/azxq/RssyTh8DVudBWTc
Euc97jLl7OuKvG0UcYkBKRQrKAJftdNkopCG/Fk1Qp+Wu+5esv4DAwKtbw2Rb2gw
NGByZskyHBW8UObQ59xmWXn7o2e/t0n3/C1qQv5PgEKPJOwaFKG9LuHfBjRDTIzA
tTFisrRQR1BHIFRlc3QgVXNlciAoRG8gbm90IGVuY3J5cHQgc2Vuc2l0aXZlIGRh
dGEgdXNpbmcgdGhpcyBrZXkuKSA8dGVzdEBleGFtcGxlLmNvbT6IYAQTEQIAIAUC
R4m9BQIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEDxD7ATuGLNmQgIAoMBb
T1bF5xyI414s9F802219JY6uAJ0dvIdr+Xs4kVLx1xZhGWeZsrwewp0CYwRHib0P
EAgA8Z92lQae5yevpKcNLsHO4FwFwsbv7k8Ye9NxoLMEXI9+tNq1v1ev7V8Orlen
YGAZKnys6ZIhYaPzUJm9e4cPO68N5gg9kI/14a1FJgLCL87zdY4NL2EO7EW9WfbZ
EiL7WNkHZxGCuL77iSOKwkwGWgKxFRwlKbtU/UP7z48GEuOfeXaZ5CM5yPWGMwWr
n8+smpX37gSl5j7YcoCvRyI7KAJScu0QRBrfud/ND9Qmi1cpTrAciAGY4EtfOPmp
5D1SOZwZoLi2LkTOOVLewfZavYA+jXGc3J23nOA6QMSRWh1INBvcQ1vuS3rKU4n+
9xSpOuPO0839n6l4X7g/QQPZ4wADBQgApyFMRDmBw5/Azk346jqEatIFF7eNVXbo
q9IO3Jr1r1NKXLJJt4G2T2Lar3QlJW4p3TjJAUHK2CfP2oEBlamJnEU5AEfKZci9
d9phT+z5XNpBIIFZYRH2zRASftm2A5A5ZhHmDCWp0WUyiNY6c4oQA41woCDAEPe8
nzIz2SjQ42Eld/eC7ukdtFIOh3c785LuQ7fClzRLrI9kmVEFt2+uPgDiqeM39At6
G7C31qad3Pc9MV2snS3hS9mbFgT6DukVV5HeS3aPOVg7Z0TB/JXwOIQHIC+VFJra
j+orSDZ80OeUyqHp9WAoUv9DPMH4+wwd8blP1frPf4XKTeYjXRXJif4DAwKtbw2R
b2gwNGCZ25Mw0xSWxWU44Q51yognp+RPKIbxGNSNfcY0LpGbZt+AkobIs/2zj4YW
itd0QhyH2U4LraOMGPMyL6Q5TJbU7vGCLCLZxCuAiEkEGBECAAkFAkeJvQ8CGwwA
CgkQPEPsBO4Ys2bUJgCfYFt+IBLXZ554/0+i5GWQW5v6d6cAnizgRfXazECi4PMV
LZxMnS9EVS1k
=LVlx
-----END PGP PRIVATE KEY BLOCK-----

TEXT;
        // }}}

        // delete key if it exists
        try {
            $this->_gpg->deletePrivateKey($key_id);
        } catch (Exception $e) {
        }

        $this->_gpg->importKey($private_key_data);
    }

    // }}}
    // {{{ testEncrypt()

    public function testEncrypt()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'test@example.com';
        $passphrase = 'test';

        $encrypted_data = $this->_gpg->encrypt($key_id, $data);
        $decrypted_data = $this->_gpg->decrypt($encrypted_data, $passphrase);

        $this->assertEquals($data, $decrypted_data);
    }

    //}}}
    // {{{ testDecrypt()

    public function testDecrypt()
    {
        $key_id = 'test@example.com';
        $passphrase = 'test';
        $data = 'Hello, Alice! Goodbye, Bob!';

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
        $this->assertEquals($data, $decrypted_data);
    }

    // }}}
    // {{{ testDeletePublicKey()

    public function testDeletePublicKey()
    {
        $key_id = 'test@example.com';
        $this->_gpg->deletePrivateKey($key_id);
        $this->_gpg->deletePublicKey($key_id);
    }

    // }}}
    // {{{ testDeletePrivateKey()

    public function testDeletePrivateKey()
    {
        $key_id = 'test@example.com';
        $this->_gpg->deletePrivateKey($key_id);
    }

    // }}}
    // {{{ testNormalSign()

    public function testNormalSign()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'test@example.com';
        $passphrase = 'test';
        $signed_data = $this->_gpg->sign($key_id, $data, $passphrase);
    }

    // }}}
    // {{{ testClearSign()

    public function testClearSign()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'test@example.com';
        $passphrase = 'test';
        $signed_data = $this->_gpg->sign($key_id, $data, $passphrase,
            Crypt_GPG::SIGN_MODE_CLEAR);
    }

    // }}}
    // {{{ testDetachedSignature()

    public function testDetachedSignature()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';
        $key_id = 'test@example.com';
        $passphrase = 'test';
        $signature_data = $this->_gpg->sign($key_id, $data, $passphrase,
            Crypt_GPG::SIGN_MODE_DETACHED);
    }

    // }}}
    // {{{ testVerifyNormalSignedData()

    public function testVerifyNormalSignedData()
    {
        // {{{ normal signed data
        $normal_signed_data = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

owGbwMvMwCRo4/yG5Z3E5jTG04pJDO6dpxw9UnNy8nUUHHMyk1MVFdzz81OSKlN1
FJzykxQ77JlZwWpgmgSZ2ooYFlwTFtr268isPxVt/Ud7nGdP/14t95dhntKV6UvZ
I7+eqPxjwKS5xPOpp8szTgA=
=AnIj
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $signature = $this->_gpg->verify($normal_signed_data);
    }

    // }}}
    // {{{ testVerifyClearsignedData()

    public function testVerifyClearsignedData()
    {
        // {{{ clearsigned data
        $clearsigned_data = <<<TEXT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello, Alice! Goodbye, Bob!
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQFHicpBPEPsBO4Ys2YRAlMdAJkB7QR6CsPnVWGAwHtZcnDd7lIDRQCgjuSh
wEaEtEDbWlck6BX0CagscNk=
=YIwk
-----END PGP SIGNATURE-----

TEXT;

        // }}}

        $signature = $this->_gpg->verify($clearsigned_data);
    }

    // }}}
    // {{{ testVerifyDetachedSignature()
    public function testVerifyDetachedSignature()
    {
        $data = 'Hello, Alice! Goodbye, Bob!';

        // {{{ detached signature
        $detached_signature = <<<TEXT
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQBHicpBPEPsBO4Ys2YRAoZyAKC8MFZMj7dsbEBzFxNld84GOLpcaACgmlBz
Jglu4i5vPA9yW2gcU9rAMl8=
=fodz
-----END PGP SIGNATURE-----

TEXT;

        // }}}

        $signature = $this->_gpg->verify($data, $detached_signature);
    }

    // }}}
    // {{{ testGetPublicKeys()

    public function testGetPublicKeys()
    {
        $keys = $this->_gpg->getPublicKeys();
    }

    // }}}
    // {{{ testGetPrivateKeys()

    public function testGetPrivateKeys()
    {
        $keys = $this->_gpg->getPrivateKeys();
    }

    // }}}
    // {{{ testGetPublicFingerprint()

    public function testGetPublicFingerprint()
    {
        $key_id = 'test@example.com';
        $fingerprint = $this->_gpg->getPublicFingerprint($key_id);
        $this->assertEquals('6BBCF2BD74A4A82F0DDE13973C43EC04EE18B366',
            $fingerprint);
    }

    // }}}
    // {{{ testGetPrivateFingerprint()

    public function testGetPrivateFingerprint()
    {
        $key_id = 'test@example.com';
        $fingerprint = $this->_gpg->getPrivateFingerprint($key_id);
        $this->assertEquals('6BBCF2BD74A4A82F0DDE13973C43EC04EE18B366',
            $fingerprint);
    }

    // }}}
}

?>
