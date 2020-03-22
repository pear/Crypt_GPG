<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Decrypt verify tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit DecryptAndVefifyTestCase
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
 * @copyright 2005-2010 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * Tests decrypt verify abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2010 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class DecryptAndVerifyTestCase extends Crypt_GPG_TestCase
{
    // string
    // {{{ testDecryptVerify()

    /**
     * @group string
     */
    public function testDecryptVerify()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('5dGf4//0CqBmlexYjyS7agt4Zn4');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258956392);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // encrypted with first-keypair@example.com, signed with
        // first-keypair@example.com
        // {{{ encrypted data no passphrase
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA5+T+RFnKO8SEAf+M1KnzLUvmJMtRTMpy3G2C8iJN1oQPznWDlL6NqxNeS6N
8ie5dXmaG9csQUx1Ys8QRaPDg6ElVIrJOXQ0CIW3mqxZS7+5X5akH5DQ0Ye4Rggx
yqADpE2z99tlYiNlpEqtG4oAUXzJjWiw8Y6MFg/xAHQUYMhEhZRB4OaSQGVPpxYs
s6YBfRGmWdNrGgPgcwoEmoHvmVKtVOfBNzO9cpl7k2pV12p6eG6jZ1qcCQkSJZlY
z2WsnDYZ9wbXuLM4XanGiJiBau0f+nJqDozmOVvc5Avz1qrQD3Dd5C5cy/e+XPdn
wzTgg3myMrwudAeJZzwMrpcrGwvdzAKE8/7TbNO+3Qf+NqfrApMVUrsFQBdzlLp9
7cV8nD0uF8ioQjPg0lzJajJdqjEkKB7h9i9fQgL/SBZ29HupsUqDoqmpCVU/B6M0
YzphMp1qWDRkk5dmpcTppTBsVx1KXCqLQFBIy+Fhc31NZRs1ccaVF3uxaOyMzFhb
FaWlUq03SjU9SlkYiFwyfyDysK3uoGeLfFh5yhH6ly5kthwLo2ov/GANF3pL0cxv
mGUcnZbkhk+MWjmz83loedhh2XpTLqRGuhzWPTQlOUQzf6xbj5zCkzWdnbqFQu19
Et5O3whgv+ufNvD5LGc/lGQeV8wV7EXcde0ISUa8LKyU+eseS+W6IHsQLPupkCQG
u9KoAQUL3Q3vX1C7WmzS2sudcAulSR8bRYfr6lJ5udRvek7M7tYdLbE1ZLua23T8
NId1euFhWftuaFjGDRvY37ab+M+zTnMtogSZDkCVyFrM2n4/hFfX9eKX6ljPxPmk
lEmn966i8e4K0jL0Ydvf7qWEVc5uov7xorYnkwvIbaW8SyUPowenfN3qODv7C0Yj
0kOgiJnRxZq+MYOR1b1L6fS0y7jDPI+er8ft
=pycC
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifyNoPassphrase()

    /**
     * @group string
     */
    public function testDecryptVerifyNoPassphrase()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('0YWPoUQhN5G4uTi45QLy3GG3RWg');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258956262);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // encrypted with no-passphrase@example.com, signed with
        // first-keypair@example.com
        // {{{ encrypted data no passphrase
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOAyS/OAcAwUtPEAf+KCytTYgKglBxxU9jAr2i0WVXhBcfyVyFq0N4or4HGMSz
zBw3eXw/JI77PY4pBxtBDCzPgSox8T8abh6OU3LDu3Zy9kvKcbQxYCSOeJkPBDpK
OtJ2Sw7CJ7QIvoSyqmRmCjrji9OU3k9ulQQ/5GauAP4QnUnt6lNkz+FOWVl5wzqc
yjXkRgfmKNBzYVscgdH+YDEUTM+edN+NflzqLk8HLU98TmINbbVJwnPvpCCvRGh4
SDDaF7WmiIjSqI15Bn7F/l+8ScxvC8EH6wxR9gqS+B9DlqVpjIoYa57SPXLcshvQ
r02OjC8d8u2oyW9TLqnTirsf347Dzo7rRwm3GbdSrgf9FoQjymAzSx6izx9BsMg+
6XJV0jSHW+jDjiJRoMAYXKc/s/y8MWRo/irCTPjReLEHWvKmISXynXqxHy1Dw5SN
1VQAPIH1ftqEVZvGtA11vLPjPYenCRCkkwz8AHqLmqZt6V2A49zPen4+H+Tp/5xr
s7TQhygo9vmTTzniBqV4lYbOyshcUTVlUErba+ffivKQPNnM+oCZXyUbJTsMlGv+
elZqUKlNEBXivHnmIbwP/vpZ1WMMewCeij1/Z6OGbbT51dh9qeqPRj96dF351Lbk
GPxLw5uP2bIzGQjGIBeKHrl2kkRxKk/MX6QPrMHR4KlUpPRfKcQLC0TGPTEPu6ya
5tKoAdoBuKYNoFk2txsseRQTI/3v5pudNsdh5R/s+PMs+HpxyaFemI3eJb05E4Jx
zGJX5UiMIb/Yr0zCvlOaDx0NjPwIoUDqtZw6YqA59/BKmaRyqGoXk0UJMK2hAJKN
yTrj0nUDWFgoKzLHu3EQtYffLUrrjVc6BB8pUmrZKBisGnXFBQvShkzdWmzUT655
JQfVfeZmgq+UAsfqIlrWBfDcqfyvWeAAZ7qH
=1oh0
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifyKeyNotFoundException_decrypt()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testDecryptVerifyKeyNotFoundException_decrypt()
    {
        // was encrypted with missing-key@example.com, signed with
        // first-keypair@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA82wFXJyxZnNEAgAwSoWLKDj/dyotGwYCT60IHC7vPGKbcbd9LMEQ8hOobKS
21aHeUBft9vlAnZabzPSqeQGYoD0BugONncV45HWlA3QD0KGcVuE6FaWIkexRNsK
S8MwVpcCgTuVkmSBgZbAS9jl7ODGGNdfGCb20fpgWFx8rv6q14aPUrD1bw5VVWeS
vLGuRGA+pcBwFlDTRvYtM0UnggfPMn6uH0CKI8uZsKkyHCu2zSCBLYsuo87sY6zJ
2UwEDyuYvr38HmcNZkb8vk7gpLCeJvFLeLYwpRrQcQy0Q+iElNPFXl5HzlwTNDq5
5IIiQNlaCV6vUKeX5VhU4i6h4yUWegVoIro4h7KwYQf8CxTrKUnI6WfDuvttU5Z7
q+7WCTDEnmOT7C2AvOKyfNXlERQnDtY1LHjJe6AEyP2RHnTrHR6Nbi4zQfl4BSZX
hH+ojM/001ir5/m8cOaMpQzHnMyUIi1HenpjJFo5fsMYg+K7j88X4KWlu3YFeB+O
xAp/mf7qUiiTKeDdGJE0u3NkFmXz/G/QDp8zwpqG+/UpiEjMm4OdFMwP68l9FWRX
d1ql5Rfeb50HPIjcmoa1iHq0IJCbT2xXxCm7QyGRy5PwSTMsQnrDUvj6zIBhqusZ
CTHqBXBH3jsDKTBJGQNwOGA418kcEpRsHY+C53rPhoUDnjzBY7dzIstQFsCy1bPZ
qNKoAfFsNjinvrwexRqkDypYLxEKs/nrMM4q+yz8n6Q2BqPT6YvOciHAkE0k4I46
STZqsFTwWxgWmhLlEFvYul3BWEp5Ow5J6+6TZrHCDIFhoQIHesxmsWVxxlgTG+0M
TS1210ua1nkP+DdWQUBzdDHFxAWWG2pUxzApIPBD2wyeLd1HMVpOjQGpFxMuO8Pd
ZcGqhMpjECMzc4DOAPFbdKwgWKXi95v4zeUf
=Ze0h
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyKeyNotFoundException_verify()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testDecryptVerifyKeyNotFoundException_verify()
    {
        // was encrypted with first-keypair@example.com, signed with
        // missing-key@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hQIOA5+T+RFnKO8SEAgAnQrKNrq6O4F0tlex+I5aklo7ElBbSPfa0k4SvX80m+n3
raM84mpnUzpoXrRa6zSM2IxzF7oWLHHAkBkWaTYdFFWegPbQk4G5rlURZDsLtamb
y3tXcOMuSMhj3b9XrR2YzfREj0AnuEvYOsd++KpjcEYgcVZOb5tCn+9UKfjop/pZ
i9sAJMYbdavxoa8DUuIMT6v0C/zNiuSFlQ23kRWB+LUR0tTIoHpb+0U0ITFLSMIr
jc9K6Zz805Tbu6xX8UXRMIdfJTJkmVWTOD8u8OUPGBxhBuZmbVfH4x+fKybcSVJJ
akqX28LjaqI+WvD/zh9l78V7foMEWd7porUzBC7z+wgAzh3LBHb2naFg4CZSVlYa
uuQ64G1ct0uxwVr0p0/4jA5nEK+WgFABPu1YPnIO3md8dBnkfs92g+0msKgB3FOn
T5+FlgkR+p2Y4knNggSmJGErCMYAq17lCu3bAlHFKwaowCBFoXrFCGBH2qgXD+CM
Rgq5gWXPLrcqnGPefdV56i+8X+t7oHCzIxX836IQICWMpOdhWMzDz44ctC5IBTJp
bDgx2pmkU+i51Q+PfK7k8eBIvlrvBGCQcUiNjCoPKAM3OjGNAQF0JraWPG2q0OSM
aZXKg9aCrQRHceCjwTf8dYRDm6yqGNeVzOnkDibPT3ySYmXKaVDbB8AquS72wE1n
ktLAxwGOjaM4MSQOGT+8eggngFidGak7957SWZRaqsXdeh6HtxKWni+XTBmWAg2m
6MnCIiVxD5A75m75ncdbRgtx2Sl9B/kCTC6Ak6hQ3iFpJKuQSZcD2gyGRSE8Ly7u
cX4jPXcYQaWLi+wVpLaYr3hSsjx2WgVk4oz+X2Kt0qQw+yWIkRw7ErmMl0ML0L7j
YePAE6UbBSR131nDKmXDUlLsV4GavAclENL5Kp6Yd8ia3h1Jdtl0waH5cCLswhf3
oi0u0bIalnZwDkFSDGiWgDQyJ8XgPFcUx8fp3dC8FVxXbd3quMxZU6/5K/dQ0LIh
+Ldlz797sLtl1lHmlaLEzTzJZriLiEiOCZeOrhbgqcGMLurzfsCWYH+BZFzH8iFJ
yDoUVsWLlvY+6gelAE9Dlzdq9m8rIALwf0Udlsdn/NBaFxarT0nl68u5fSJo8UA2
MuZd2EB/BKXWvAo5Ea9CQ3DrrDkbwlE3PKrWlMos6dFb/SWxtmKfEeNYhYJsbwsv
x5MBl/I2kBCHeH4=
=hojs
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyKeyNotFoundException_both()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testDecryptVerifyKeyNotFoundException_both()
    {
        // was encrypted and signed with missing-key@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA82wFXJyxZnNEAgA0oz13vLInSM0GlhLyIQ5fRXlttY6jOO6xgUH3MhCqExN
KWLBp9VE+iAzdsnF8hjP+u48qNjYj7Jvyiu8vf1SD9ScYoEiKar0EhZVLfCxX7PC
4ZWCSEWD5h5nBSabdL00f3vL//GrQtMAwcKP4p+pEyxTEoSg7xp10+F0JqnhlIqh
vsOeP4vAeYi1v7x0UyoNxzHbfGb3gjwNaWEixBPMekoEnZ8SOORL5yrOctOjcFxz
hKQFIcJv5vG/Ozs6Wm5q+uvzkZDc2X2dOnb1SpCP5cxNC0g37CiwPIL8ArBcu+yP
5HSC8YhyyVcQTuIdb0a9t/IK0HNfEOF5gCBCQ462Xwf/X3PQgKvvK76DQ8xvukB8
6yKwaHv2K8NWFyTuPppiiRztVI13zPt/Jjw/YPNE/qUzONiggqWM0tGtVkbNRzic
dMEaAfwmZSix0alMPnDuVNyq9AnCUEjkXKTByWDL4pejvB541dA+rtU1D8pV1/8X
P+oQ+j1EnJitYSTdsnD4YC88/q2RnQTmibmyMclVVk3el6OvZN0Gj0Y2bd9c4LC+
1reFYZHrX0FcsGIVuHEK/VikTqoWhFOTYUFXFGSE/AGvotfHj2QG3sd297IaSbVi
C1LwWGvpdZ2yw4RV4Zgrqvg8WOL9maj/mX8aE9/gzs9XH2vuucDBOC0RrQPsM6wb
ANKoAdExlp+92b69YSNjP2bRQFjN3gFKaGfBm4ULUhRTFnlfBGIIa+2KHUNB7dYk
obUon363/o/8wdmlXewIwPLK8nQsYXhAyxJcf9o90tqv1L83ZMMLU7FqBkUCmT4a
9EPXbxnaeO3sa8ZuGm0ilGuIFsK24pBOXtYESZ4ix6y7PZOXCJDun4+dFKcfMG+0
t8TnSlDaIKEuve9kUGwmO8Z3LsYJEsRCsHyN
=YNhC
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyKeyNotFoundVerifyIgnoreErrors()

    /**
     * @group string
     */
    public function testDecryptVerifyKeyNotFoundIgnoreVerifyErrors()
    {
        $signature = new Crypt_GPG_Signature();
        $signature->setKeyId('8E3D36B1EA5AC75E');

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // was encrypted with first-keypair@example.com, signed with
        // missing-key@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

hQIOA5+T+RFnKO8SEAgAnQrKNrq6O4F0tlex+I5aklo7ElBbSPfa0k4SvX80m+n3
raM84mpnUzpoXrRa6zSM2IxzF7oWLHHAkBkWaTYdFFWegPbQk4G5rlURZDsLtamb
y3tXcOMuSMhj3b9XrR2YzfREj0AnuEvYOsd++KpjcEYgcVZOb5tCn+9UKfjop/pZ
i9sAJMYbdavxoa8DUuIMT6v0C/zNiuSFlQ23kRWB+LUR0tTIoHpb+0U0ITFLSMIr
jc9K6Zz805Tbu6xX8UXRMIdfJTJkmVWTOD8u8OUPGBxhBuZmbVfH4x+fKybcSVJJ
akqX28LjaqI+WvD/zh9l78V7foMEWd7porUzBC7z+wgAzh3LBHb2naFg4CZSVlYa
uuQ64G1ct0uxwVr0p0/4jA5nEK+WgFABPu1YPnIO3md8dBnkfs92g+0msKgB3FOn
T5+FlgkR+p2Y4knNggSmJGErCMYAq17lCu3bAlHFKwaowCBFoXrFCGBH2qgXD+CM
Rgq5gWXPLrcqnGPefdV56i+8X+t7oHCzIxX836IQICWMpOdhWMzDz44ctC5IBTJp
bDgx2pmkU+i51Q+PfK7k8eBIvlrvBGCQcUiNjCoPKAM3OjGNAQF0JraWPG2q0OSM
aZXKg9aCrQRHceCjwTf8dYRDm6yqGNeVzOnkDibPT3ySYmXKaVDbB8AquS72wE1n
ktLAxwGOjaM4MSQOGT+8eggngFidGak7957SWZRaqsXdeh6HtxKWni+XTBmWAg2m
6MnCIiVxD5A75m75ncdbRgtx2Sl9B/kCTC6Ak6hQ3iFpJKuQSZcD2gyGRSE8Ly7u
cX4jPXcYQaWLi+wVpLaYr3hSsjx2WgVk4oz+X2Kt0qQw+yWIkRw7ErmMl0ML0L7j
YePAE6UbBSR131nDKmXDUlLsV4GavAclENL5Kp6Yd8ia3h1Jdtl0waH5cCLswhf3
oi0u0bIalnZwDkFSDGiWgDQyJ8XgPFcUx8fp3dC8FVxXbd3quMxZU6/5K/dQ0LIh
+Ldlz797sLtl1lHmlaLEzTzJZriLiEiOCZeOrhbgqcGMLurzfsCWYH+BZFzH8iFJ
yDoUVsWLlvY+6gelAE9Dlzdq9m8rIALwf0Udlsdn/NBaFxarT0nl68u5fSJo8UA2
MuZd2EB/BKXWvAo5Ea9CQ3DrrDkbwlE3PKrWlMos6dFb/SWxtmKfEeNYhYJsbwsv
x5MBl/I2kBCHeH4=
=hojs
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg = new Crypt_GPG($this->getOptions());

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerify($encryptedData, true);

        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifyNoDataException_invalid()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testDecryptVerifyNoDataException_invalid()
    {
        $encryptedData = 'Invalid OpenPGP data.';
        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyNoDataException_empty()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testDecryptVerifyNoDataException_empty()
    {
        $encryptedData = '';
        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyBadPassphraseException_missing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testDecryptVerifyBadPassphraseException_missing()
    {
        // encrypted with first-keypair@example.com, signed with
        // first-keypair@example.com
        // {{{ encrypted data no passphrase
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA5+T+RFnKO8SEAf+M1KnzLUvmJMtRTMpy3G2C8iJN1oQPznWDlL6NqxNeS6N
8ie5dXmaG9csQUx1Ys8QRaPDg6ElVIrJOXQ0CIW3mqxZS7+5X5akH5DQ0Ye4Rggx
yqADpE2z99tlYiNlpEqtG4oAUXzJjWiw8Y6MFg/xAHQUYMhEhZRB4OaSQGVPpxYs
s6YBfRGmWdNrGgPgcwoEmoHvmVKtVOfBNzO9cpl7k2pV12p6eG6jZ1qcCQkSJZlY
z2WsnDYZ9wbXuLM4XanGiJiBau0f+nJqDozmOVvc5Avz1qrQD3Dd5C5cy/e+XPdn
wzTgg3myMrwudAeJZzwMrpcrGwvdzAKE8/7TbNO+3Qf+NqfrApMVUrsFQBdzlLp9
7cV8nD0uF8ioQjPg0lzJajJdqjEkKB7h9i9fQgL/SBZ29HupsUqDoqmpCVU/B6M0
YzphMp1qWDRkk5dmpcTppTBsVx1KXCqLQFBIy+Fhc31NZRs1ccaVF3uxaOyMzFhb
FaWlUq03SjU9SlkYiFwyfyDysK3uoGeLfFh5yhH6ly5kthwLo2ov/GANF3pL0cxv
mGUcnZbkhk+MWjmz83loedhh2XpTLqRGuhzWPTQlOUQzf6xbj5zCkzWdnbqFQu19
Et5O3whgv+ufNvD5LGc/lGQeV8wV7EXcde0ISUa8LKyU+eseS+W6IHsQLPupkCQG
u9KoAQUL3Q3vX1C7WmzS2sudcAulSR8bRYfr6lJ5udRvek7M7tYdLbE1ZLua23T8
NId1euFhWftuaFjGDRvY37ab+M+zTnMtogSZDkCVyFrM2n4/hFfX9eKX6ljPxPmk
lEmn966i8e4K0jL0Ydvf7qWEVc5uov7xorYnkwvIbaW8SyUPowenfN3qODv7C0Yj
0kOgiJnRxZq+MYOR1b1L6fS0y7jDPI+er8ft
=pycC
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyBadPassphraseException_bad()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testDecryptVerifyBadPassphraseException_bad()
    {
        // encrypted with first-keypair@example.com, signed with
        // first-keypair@example.com
        // {{{ encrypted data no passphrase
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA5+T+RFnKO8SEAf+M1KnzLUvmJMtRTMpy3G2C8iJN1oQPznWDlL6NqxNeS6N
8ie5dXmaG9csQUx1Ys8QRaPDg6ElVIrJOXQ0CIW3mqxZS7+5X5akH5DQ0Ye4Rggx
yqADpE2z99tlYiNlpEqtG4oAUXzJjWiw8Y6MFg/xAHQUYMhEhZRB4OaSQGVPpxYs
s6YBfRGmWdNrGgPgcwoEmoHvmVKtVOfBNzO9cpl7k2pV12p6eG6jZ1qcCQkSJZlY
z2WsnDYZ9wbXuLM4XanGiJiBau0f+nJqDozmOVvc5Avz1qrQD3Dd5C5cy/e+XPdn
wzTgg3myMrwudAeJZzwMrpcrGwvdzAKE8/7TbNO+3Qf+NqfrApMVUrsFQBdzlLp9
7cV8nD0uF8ioQjPg0lzJajJdqjEkKB7h9i9fQgL/SBZ29HupsUqDoqmpCVU/B6M0
YzphMp1qWDRkk5dmpcTppTBsVx1KXCqLQFBIy+Fhc31NZRs1ccaVF3uxaOyMzFhb
FaWlUq03SjU9SlkYiFwyfyDysK3uoGeLfFh5yhH6ly5kthwLo2ov/GANF3pL0cxv
mGUcnZbkhk+MWjmz83loedhh2XpTLqRGuhzWPTQlOUQzf6xbj5zCkzWdnbqFQu19
Et5O3whgv+ufNvD5LGc/lGQeV8wV7EXcde0ISUa8LKyU+eseS+W6IHsQLPupkCQG
u9KoAQUL3Q3vX1C7WmzS2sudcAulSR8bRYfr6lJ5udRvek7M7tYdLbE1ZLua23T8
NId1euFhWftuaFjGDRvY37ab+M+zTnMtogSZDkCVyFrM2n4/hFfX9eKX6ljPxPmk
lEmn966i8e4K0jL0Ydvf7qWEVc5uov7xorYnkwvIbaW8SyUPowenfN3qODv7C0Yj
0kOgiJnRxZq+MYOR1b1L6fS0y7jDPI+er8ft
=pycC
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('first-keypair@example.com', 'incorrect');
        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyDual()

    /**
     * @group string
     */
    public function testDecryptVerifyDual()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('TAsI7RYUgZAud0wMZu3Iab3bZXo');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258955651);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // encrypted with both first-keypair@example.com and
        // second-keypair@example.com, signed with first-keypair@example.com
        // {{{ dual encrypted, signed data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA5+T+RFnKO8SEAgA2lVokiF7FeQvT0EjgH/X2mXNbz8ukKM7WdIAsIFumg1a
Skfsqn1plAHs3f3OhY16tBb1WW4J8WXEt6g3yHls92XpRUgRTUjVCr4HIvMwSB3A
V/ZQdGs3NK3wh0rMu6q/Ski10dEwP7SUE+w19AmiCQfmKYLUJmCgPLmVm4IapAad
lIpNalUHzXhHuuIzKut9H0n6+p0jUPW2JehFFGud66MS5PaGbDPZS2lKiPjytSzl
pYipuglregaaMR5KsBYxP4A6MnMaRaZriTeItROJ0PTBMaq93+IyrnwulqEsWk6t
8ahRM4FmC+U/Z9tgWxTEKU28zthjxKXW5JOceGxeBQgAoxRAhd75Ok406YG4VucC
rxLSLIKIt0TAlbTWncJq9qhLA86+RL4oqUYfDjq9o9lrfkPQO3xfHam/43j2yaF3
HeJwSDwU0V4YZ6R9ZVdHMYw7w7yynn2HmNesDUWRfI7IRwMFtgKGvv6qpdUOYmWN
MhQ+HxnwMgvHNaz6TRYpQzVvtpB6q9J3/xCM3+uKxDaJLbJux50s6FpnCRnLpGWs
1Tj8l9BSMlAGtP6dMR3MysZS/UnXwdTmDFR9ARS+HxsP89I95UAKLWaouShoo9dX
QIs0pLkQs+CWpjPVAp8TT0Vj1juThk4bJarti/BaZOyzUAOrleDWOO8VVsuM1Bw2
xIUCDgOy9U5HV+IkUBAIANU8DKkvHNzkx68XvxXXVsBsWTGNznrNGUjqSfhyS9pW
lRnq7qB2c2UgMvMTnMWyogQ/gKEotdeqKCXdMLBkataB1xkMbCvUZzdj2A/OPtDD
xT7ogqn82YaEjlfEqEbqBi1lvq2tuC/YsGti0c6zDUFoZax6QWL+NU3eCY6ZxBSx
NuZ4hiBJqPeHVP92SCnsC2BwqUy7W0rUuKnXo3VM1syd98TZjdM6SqBVQ61YX3u2
rS1YiphYd2WeNU/bSZ79bHMMPt3joQ+nCGKvGSIlCVxAy4EPWDb2KFw0yUmXUub1
tLnrKAOdufWC780LuhgINLb1PSmzogRmvk4ih687h9wH/0hx4olXvkUHZAcpnMHT
zGK8NQeoxfSmcJrYNa1TpQ8FjLad7eycnoIASC4qS7IsJ0xzedWd2eqLdc+9qIiv
68gW2MjZOqQ5PvcZk1eqOVUNH8Ua8Wfv82ljk1VE0L9zzrS8nGLq5prjaK400Vwh
MVh129jyjkpgGZhIHC4cNGBQl1zKDw9WWd1Rk92rpmsvb7JZVNDg0DjW3hrwc7v2
WbGqEXG5Sown6J1gX4wKIpn9roOE9ZSu1hvugPc28IZIne4rL05Pd4qVnp87SiUh
wHs82nXGhqcscZx2NiT2F///6j97+ccd+619iabKkpfwGunQZHfxit+7bfHuX+5O
tFHSqQEsRi3gNrRlMRDnPjLHXjR+x80anNOwxBfZP1qjdTsFucqmZ57KUdIpUGmi
uRgBZhuVRz8ryTcw5/nACkeKLkxOJLHGgNDilJtNO8tv+BbQDRZzsNYTM7ZNcAo4
JqkWrMb43BTbAbdgTyEkWhqw6cFQEePYqXcbeDh3c77U5joGZW+iPZQlJbBCMC6e
KBH+5iH8NzPpP6yZq5e5p1ZOkb2PY3EXtL8aemU=
=S/2J
-----END PGP MESSAGE-----

TEXT;
        // }}}

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->gpg->clearDecryptKeys();
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);

        // decrypt with second key
        $this->gpg->addDecryptKey('second-keypair@example.com', 'test2');
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->gpg->clearDecryptKeys();
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifyDualOnePassphrase()

    /**
     * @group string
     */
    public function testDecryptVerifyDualOnePassphrase()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('3OJnX+PqHI0YUCeFxICCxhPHY1Q');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258955916);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // encrypted with both first-keypair@example.com and
        // no-passhprase@example.com, signed with first-keypair@example.com
        // {{{ dual encrypted, signed data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA5+T+RFnKO8SEAgA7zHd9KH/C2GCM9H7pdMS76PXGfmhGPyQAtokBQgF8G1/
orldCnTUnxmZejbOwYhYVEh5zlnYshlCpUSsGBw+sH7XiC8eorCD0YJj5NDBp8W6
VtvGkMqqG9tDJk6TfKornFl+H7xpiwXox5T/swnpJcJ6qaTXBtLb7HViiwTTu5Zk
QbWqSvIOigIkiuTnv898/eeEIh9gg6ScRVZOyZ7P2usDaOWqVVNJmkaLIaWxOYck
Go3hnYAhkfjpMcgAMkqtXPWIS8OrfY8wOXxXNA4EjvrHs+5/yHbZmj/5bBA9CuGJ
UctQqF9ZtZsagSpK0WTJCt4RkX3jKqK9tJVQzBuKZgf/Up3Zi6Lfg6iINm4qsd1h
Dusuuxw0vgGoMc6P7QOMFmeSs3g/yYQKaHomWqEVg0LpC2FHOqceqZRZJd4XMcsz
uCF95lx7Tm1ozgEhBgQNSQVoAA5/MYXlKo3YQGEIyU9Gx4f2v/8XV3umYXjGfJY9
adBHLIvPFeeze1/f11ztZsgLr3DBP01/O6qLi91dwsqpzQXzjurVYIHJdCD+JviZ
2CjwkcpUTHx5vXNiobMcBjtogjP7d4W8DJ0La5+WVujV0nxHiE9mEXuct8TajCY6
/40UIdtHEPWc08ccXXjQaFKbJxYGDMOJzQ8LPdHqa3RubmMADqzH4W3/SSmRsibd
4YUCDgMkvzgHAMFLTxAH/R3ryj2BUP6C/aYfgGqi+FOVoHVR5kiz6Z2nBEKqntwZ
njdKD+pvuw9fxaNhNNZy3UlKnIdonNb/A3upEeR81opP+HWCgXUlcgucQ7VXiUPd
mnQAR+cTrFgTXf+B54VHwDED5RVDm4/e29casiNyULm6xWFYqfJMGBvEGrflq1BW
QSYlpc0ijqkER+VNy49Dy/qY1TRUBZ84+RmL2L/18zQbdekMoLUDxJOEoo0C65ER
5ReLlFN2nI0MC8O5ZU8PfjDXXQ7qnQhz/2kxorNiQl654V7ZsEWkVLF9yejZXSzU
ynWANJdCnWLMjOnrQPm1+b2Yi8pcgtpIPsBdTIHn4fAH/iW0Uxltx9ZrV7kvrDDj
Izc4/ocn3Z0c/47Rv62MTYcxVYzFdP+WxisMI2LV88g1Zu9rOKR1k7UkNGNlfklS
5CSApTnm3MC9/w54dacPohZ7SrQlTSHJxfRINH7H3DOuaH9awf+ntwUks73mXjT5
ikSJ2D05Kbf8++jLhRRKLPZS8bOmSw2KTaCbtk7LX4pEIu9d6kig6g8Wj3h9dlQs
QXCKL14/8cSGrxXXWHOuL9abnxZTwenbn5B5FqBPoiRKqSFToiLd/pBWjG/aieju
Rm+Uyyddl+ISJUnv0AAiOxfifJmTdUsT5LZLkYG4CUyX2T3JiZ2L4msF4S3U70wp
PtbSqAG3xVRFlZY2jLeW8btez7XkzB9fhvVd1Hee6EXRnF5/BcLkqy8sYvx1MHkT
eMzttOs1NRrjXy4+zUqo//59gQ46zwYd0NA/Ga6pl1kn8+xM76DCcI4LhdZN75rR
ZUcyEqBKX9RNefMD7cR6kYoljGfnT3Mjd+0eTdF/Glk0ElVjbMtQclG0o/7wlI7m
+b2E6/e0qZedOCq48+mIRv0tjRuoFiydM88aGg==
=IgJ0
-----END PGP MESSAGE-----

TEXT;
        // }}}

        // decrypt with no passphrase
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->gpg->clearDecryptKeys();
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptAndVerifyDualNoPassphraseKeyMissing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testDecryptAndVerifyDualNoPassphraseKeyMissing()
    {
        // encrypted with both first-keypair@example.com and
        // second-keypair@example.com
        // {{{ dual encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA5+T+RFnKO8SEAf7BO/zLK6gDt5epMOEnHc9ESdSTy8yExdoSxHhvTFxWfwi
AwMtBEur8sotSVt+Q87xYzjzE77+FQYS9oYCivlK/Nedblj3MiRuUWhM+Q9tbP3b
KbwEwaQlrpNphQsKZOWkliZWmFJWnQ1s1Pm6lPlhwTNhcwkapm8EXuWFExJnY9yW
EZjUOhVmnkitKykKup8Brvfm2QpGXoFZtHFKXTi162Lue9N0tDm6s3JnCIhMFQgI
fyAikcsJKpbUgeGmzlWJO8QkH81QMuKpqfUb8R1dswhDp6RKXhoXS43zkhH8QSbM
Cp9AWdv3qsWBUqzWavCxjtIsogYO+gFLl/Vuw5Y87Af/b7OQgLP1v6xKZcrTvFCF
hxGxn+5M8E2GyJaKpQ1GZ+Wv+IzPGetm7rWf6q71hchAkxFMczIPSK7aARm9CNVo
7tCdcUmUTgLhG1/0OfmkbwJUjdSpOtz8+TvIZa20Jj9a1G8WT3KTeivKMqBPhgk4
sD7OJPDCYQNSQEw6pAn4oBrhJlDUkpCK6wIbUhzeq3MUwtM1e+qpCr/k4In4NVq6
cmoC7W//9J69ecuxmiUHRhZ4CALRxQMAsSxMRnNJ26JY4ko82Rfvbrz8QEmKcIyT
bTdAMsZ18m9XXrnc2ACDDMQyUkneQDUZSt7V67ZiN4Upi295CynIbNEMmcH/13Aa
aoUCDgOy9U5HV+IkUBAIALGICOFzyfquWZ0ZhPGVdDWx1yNcApnzIgZx1JbBpMyc
2jb9aQHwGId26gv/ym/M/3FJ0lv+IAcktMjO4dwYLnUuBa6BOFFybZi3gYvXtSuy
iW4ygVjIsYixhvbsyaVCoB/MsNBFrQAHEShaxALBkI/dv+yyD8BifU4Yj9LFcAZO
mFDraOgYfHsur5eevYTXozf5wU7phu9v6zo5bk8zgZSqs8AgyscstZWCqCtR/cG0
t9lAIovGPsIcA12qvkm/A0WiBMEWhGryzHTv9oRsFztOFtqH+MmLdlvWjElw8hKt
fFJB+bhHNO9BUIrwnuH79cA4aXOy1+xG+ECs7oJbcisIANqJKalQLgBYEjbucpDg
O8i/c4RmV9J7VczpZp7ZREMpTmv9nV849OFXT1strsb/+vXOXOyLToG1gOxRfJr2
q9jFjpyMAtrr/aHhXMKK1OMhhcdkQMEKuHTvon5KleZOQoVmIqa3kUtWNW1vFBIP
UfJFH202EJLOLC25rXCtzRsJE0HWiYDyLqKMQcSQhTcngLBLmeDLH3DeGUIDwcZe
oWgUg8wB/oSoU4AchShzO+yM6bcmffcaHFqwll9gdu9walnJAAOb8+r6LGGlsGTV
qhnR0LM3Khp+HOFdaxcQT6BV1aw/D6Z5hIi+Am0VTi0HlFr/gwleyYaP+742Z6K0
s8bSVgFT2Pjik+byARWzRwWjmi0jT7QsgITM73aBKPDXiArEPkv8YtC9HzUj0lCY
gX7Eg2ZqISULFydBckMJ6drojMMQiqZBeEc09GupSBL1zldnKHfiXBTw
=QYjj
-----END PGP MESSAGE-----

TEXT;
        // }}}

        // #21148: Make sure that proper exception is thrown
        // when decrypting without specyfying a passphrase

        // in this case we remove one of private keys to make
        // sure proper exception is thrown also in this case
        $this->gpg->deletePrivateKey('first-keypair@example.com');

        $this->gpg->decryptAndVerify($encryptedData);
    }

    // }}}
    // {{{ testDecryptVerifyDualSignatories()

    /**
     * @group string
     */
    public function testDecryptVerifyDualSignatories()
    {
        // {{{ signature1
        $signature1 = new Crypt_GPG_Signature();
        $signature1->setId('7PujVkx4qk28IejcD6BirrwBmRE');
        $signature1->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature1->setKeyId('C097D9EC94C06363');
        $signature1->setCreationDate(1258956025);
        $signature1->setExpirationDate(0);
        $signature1->setValid(true);

        $userId1 = new Crypt_GPG_UserId();
        $userId1->setName('First Keypair Test Key');
        $userId1->setComment('do not encrypt important data with this key');
        $userId1->setEmail('first-keypair@example.com');
        $signature1->setUserId($userId1);
        // }}}
        // {{{ signature2
        $signature2 = new Crypt_GPG_Signature();
        $signature2->setId('AhrDdkdcBsEsOSQOYENhl5C7auc');
        $signature2->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $signature2->setKeyId('03CC890AFA1DAD4B');
        $signature2->setCreationDate(1258956025);
        $signature2->setExpirationDate(0);
        $signature2->setValid(true);

        $userId2 = new Crypt_GPG_UserId();
        $userId2->setName('Second Keypair Test Key');
        $userId2->setComment('do not encrypt important data with this key');
        $userId2->setEmail('second-keypair@example.com');
        $signature2->setUserId($userId2);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature1, $signature2)
        );

        // encrypted with first-keypair@example.com and signed with
        // first-keypair@example.com and second-keypair@example.com
        // {{{ encrypted, dual signed data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQIOA5+T+RFnKO8SEAgAzllqH/z2ThJcXteCxPJu97EmMpqdipbcSUAjGZJ5hQFe
YlKbrxL30W6VYgZIPqP5FubZkI8WHWqDZwbtphk5l+o8nfyNV4el/JHHEmf/mzIM
UmBXJFVa6g9CmS/SdhYhO/ovMeBsNVA1+Er+Cdyh9sTpX89I3zlehgwcXtv/di6W
fjzeg5Na/39KfYWEyXPB5EUkWG4hmnGo63GPUEsxfNXbKDafUtTwOFop+1+wMVyA
kJbOEaaiTSzvbpa+ruRisv34a6vX8u6QGqPSZ43vgmKeWfPEBS8p7bdRFGECLNvP
gK4tIwlBI0o13JJ/lnjL6dR2f7qls/0dxBGxhjFpjAf/bn5d8r7e2N1yJqh1C5T0
/n/ngN1bHDsQhrAPMJfJre7qJxZEiHa8dfagdDU6I/EC4w1ouUYKWrzf9sPKTxs+
QosiqrGKYUO1V46EzRXc72PZBKf5CZBBvRZv3GzzcVtroViiIshyAp3TBPk2GC+N
ilmEm72CWgQHKqg4vX1hbTCbOEu/YDmjF9Vb9a/zT5RAKDjBrcc9tkPdVMfDfI2Y
Ly6CvL2DSvBUNbAShl2TXdTdylYbopyiFhOBvJoeidFVwIFX303nFUBMUfbCT6WK
MGZGzXrNZlRyKfH9UCj+5pxom2TMpu+URfvXtByUGfNst+ZRi+ADOnbc51canwWc
M9LAKgG6SF2OhrDTTe+KASz3dFbpD4xnczl+686GGT76W55YKQNDff72bhx8lBnP
XiM+CsWGPLZdoOCQU+SEWD7lJ1I6fB+l/oFWC2PVlDjrCS1Nn/L9i5p+EqNzcUVB
JR62EaLPsOFOfNeHhltuz2aYkvQT4sDPeKkpBKJDp2ejMy3V9ZXia1D2ZTCfMp+J
GEu2SS68qlZV12gpSwY8BpS/nirx5aUQ9VhjlSN3GHF/r6j91VsHJhmU+nmWPWaF
mHfMGHS5sw6+gz3SyW6b4TlUnnx412nhFinanxBlwkuAcukgL8k+OesoDX2a1Q==
=TW+z
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifySignedOnly()

    /**
     * @group string
     */
    public function testDecryptVerifySignedOnly()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('LS9EdhGLaEUllGk3Snc0Bk+Cn3E');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258956761);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // signed with first-keypair@example.com
        // {{{ signed data
        $signedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

owGbwMvMwCR4YPrNN1MOJCcznlZMYvDmUr/pkZqTk6+j4JiTmZyqqOCen5+SVJmq
o+CUn6TY4cbCIMjEwMbKBFLIwMUpANNttphhwWm3a/VsLcc+u0x4/Xtyuk/Xiqd3
ZzMsuHZrvkPCHgUTgcXFLt6GVRlPYvT5AQ==
=ehgC
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $results = $this->gpg->decryptAndVerify($signedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifyFirstSubKey()

    /**
     * @group string
     */
    public function testDecryptVerifyFirstSubKey()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('YUeHL9fEAK4hMokvXsNgUP5vaJ8');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1267228319);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // encrypted with first subkey (ELG-E) of multiple-subkeys@example.com,
        // signed with first-keypair@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQEMAykh4NP/Ww9KAQgAhB2Ww2jNhy9ISQ/+S52eROzbN8ij65GoL9tTHK5TZp82
mv+ieGwobe5PGYdBEvQdsSrKyF3x25oaEyjaOa+39DtmF82OZKZ3tIO3EJ1qvn8q
SHxwiKYa4MOgwER9pT7i/YZOZuIdII/NeuVuGxbsa5qdISltKkE7WS7yWStcDJi1
goaPx3G1cZIVnTgSncK1YE4j2TZXBxI/zuuuH0pbZk7rK+K9zIeyYD1YZFagrjJh
REN5QbnT1v+1HXno1WRp4Obo072i3FjF505U1XLQ5p2/d55m73jfBJoqpb2NExdU
KimXnQZ+8/8ddzL3ZP4+g982dmLFvl2/h7KGtPOMbdKoAeMQYVolMDoQp6+nyQHP
CgpeFJY5+VnxNq1wEgJgXTo79xohN59wwad1ltcUGAVC49RMHbX+xBjR/HPCG9yt
QTwMes514uPYbNL6cGoKm7dt/zQL8YsjvfswGE06bj/rU3JCTDnR+iOUDHzUMDEn
jH7Vbs+9D1E9t5bSJs/8e7rzhZKF1AhunUdDmc4vPPJMV8xKF+o3h3nKQ6wEoOMz
f6XGFW8cvNAl
=vSGT
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('multiple-subkeys@example.com', 'test');
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifySecondSubKey()

    /**
     * @group string
     */
    public function testDecryptVerifySecondSubKey()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('ZLZFDxxO+zdCEklUu6eppBCPCsA');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1267229043);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => array($signature)
        );

        // encrypted with second subkey (RSA) of multiple-subkeys@example.com,
        // signed with first-keypair@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.9 (GNU/Linux)

hQEMAykh4NP/Ww9KAQgAs1xviSlaTTGXWNzT43giUSf7SnYoeoyYqZt/eo7c9eHu
sLGdhhpQeUiU5vW6UsOvs3QLx3hR9wYunUOKmDJmrrtVglsZIjuHU7oYlveozYwG
wlHNbesQlWyMNSQPDeGWAQAnOUU2jv/9nb93SLYlkDKr1qjn9qjZ4Kl2q1Yi4PSu
LaqI3r1LdJbFmEB6vQ8o6GiIpaFaZapK6vloPoq5xbaALAfAiSg58+IwV/Mn190L
T0tmFCUuTm/Px8fv5xe+mPW2pMUovhJhBrhBopEcWNHpxuNbxwac1T54COZxjC8W
L0XpYW7c3XVdO6VqS4pSnz+zo5EYcU2Sk6mfpN5ki9KoAdPZ4ICMe0OWIjMxgApI
AVHaKowZ6+xSW8vLRzWjJTZrlEoMjwJSOJwCsMcsu6MwJOFcVEl4Mc3TiAMsUHWf
6f/pHb7W2Am12CfJaaU0+nDQrlKOw5DfQG5YEG/LrpjXGugVWMQH/31MMKawSAP3
QgdXe417ZeMtsHVaz/W1Za5ZpRpcwoT5N31LfNV+SoIpajhmtr79aeg8d6OH8H+l
7kLEDVlh9DP0
=I21n
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('multiple-subkeys@example.com', 'test');
        $results = $this->gpg->decryptAndVerify($encryptedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifySignedOnlyBadSignature()

    /**
     * @group string
     */
    public function testDecryptVerifySignedOnlyBadSignature()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setValid(false);
        $signature->setKeyId('C097D9EC94C06363');
        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedResults = array(
            'data'       => "Hello, Bob! Goodbye, Alice!\n",
            'signatures' => array($signature)
        );

        // {{{ clearsigned data
        $clearsignedData = <<<TEXT
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello, Bob! Goodbye, Alice!
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.6 (GNU/Linux)

iD8DBQFI0vkCwJfZ7JTAY2MRAgzTAKCRecYZsCS+PE46Fa2QLTEP8XGLwwCfQEAL
qO+KlKcldtYdMZH9AA+KOLQ=
=EO2G
-----END PGP SIGNATURE-----

TEXT;
        // }}}

        $results = $this->gpg->decryptAndVerify($clearsignedData);
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifyFile()

    /**
     * @group file
     */
    public function testDecryptVerifyFile()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('kVwy2yYB0TlXyGd9FUvVYp5jCoI');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258220197);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedMd5Sum     = 'f96267d87551ee09bfcac16921e351c1';
        $expectedResults    = array(
            'data'       => null,
            'signatures' => array($signature)
        );

        $inputFilename  = $this->getDataFilename('testDecryptVerifyFile.asc');
        $outputFilename = $this->getTempFilename('testDecryptVerifyFile.plain');

        // file is encrypted with first-keypair@example.com
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );

        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);

        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptVerifyFileToString()

    /**
     * @group file
     */
    public function testDecryptVerifyFileToString()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('GTvYFmQ5yfMM/UOffkYCx21Se2M');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258221035);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedSignatures = array($signature);
        $expectedResults    = array(
            'data'       => 'Hello, Alice! Goodbye, Bob!',
            'signatures' => $expectedSignatures
        );

        $inputFilename  = $this->getDataFilename(
            'testDecryptVerifyFileToString.asc'
        );

        // file is encrypted with first-keypair@example.com
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile($inputFilename);

        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
    }

    // }}}
    // {{{ testDecryptVerifyFileNoPassphrase()

    /**
     * @group file
     */
    public function testDecryptVerifyFileNoPassphrase()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('unMY9l/f9sFaMvMV0H1ZuNJRY6Q');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258220226);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedMd5Sum     = 'f96267d87551ee09bfcac16921e351c1';
        $expectedResults    = array(
            'data'       => null,
            'signatures' => array($signature)
        );

        $inputFilename  = $this->getDataFilename(
            'testDecryptVerifyFileNoPassphrase.asc'
        );
        $outputFilename = $this->getTempFilename(
            'testDecryptVerifyFileNoPassphrase.plain'
        );

        // file is encrypted with no-passphrase@example.com
        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );

        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);

        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptVerifyFileFileException_input()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testDecryptVerifyFileFileException_input()
    {
        // input file does not exist
        $inputFilename = $this->getDataFilename(
            'testDecryptVerifyFileFileException_input.asc'
        );

        $this->gpg->decryptAndVerifyFile($inputFilename);
    }

    // }}}
    // {{{ testDecryptVerifyFileFileException_output()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testDecryptVerifyFileFileException_output()
    {
        // input file is encrypted with first-keypair@example.com
        // output file does not exist
        $inputFilename  = $this->getDataFilename('testDecryptVerifyFile.asc');
        $outputFilename = './non-existent' .
            '/testDecryptVerifyFileFileException_output.plain';

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptAndVerifyFile($inputFilename, $outputFilename);
    }

    // }}}
    // {{{ testDecryptVerifyFileKeyNotFoundException_decrypt()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group file
     */
    public function testDecryptVerifyFileKeyNotFoundException_decrypt()
    {
        // file is encrypted with missing-key@example.com, not signed
        $inputFilename = $this->getDataFilename(
            'testDecryptFileKeyNotFoundException.asc'
        );

        $outputFilename = $this->getTempFilename(
            'testDecryptVerifyFileKeyNotFoundException.plain'
        );

        $this->gpg->decryptAndVerifyFile($inputFilename, $outputFilename);
    }

    // }}}
    // {{{ testDecryptVerifyFileDual()

    /**
     * @group file
     */
    public function testDecryptVerifyFileDual()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('7TYk0hpio90QZHHHb4UtgCWAEq4');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258220362);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedMd5Sum     = 'f96267d87551ee09bfcac16921e351c1';
        $expectedResults    = array(
            'data'       => null,
            'signatures' => array($signature)
        );

        $inputFilename  = $this->getDataFilename(
            'testDecryptVerifyFileDual.asc'
        );
        $outputFilename = $this->getTempFilename(
            'testDecryptVerifyFileDual.plain'
        );

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );
        $this->gpg->clearDecryptKeys();
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        // decrypt with second key
        $this->gpg->addDecryptKey('second-keypair@example.com', 'test2');
        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );
        $this->gpg->clearDecryptKeys();
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptVerifyFileDualSignatories()

    /**
     * @group file
     */
    public function testDecryptVerifyFileDualSignatories()
    {
        // {{{ signature1
        $signature1 = new Crypt_GPG_Signature();
        $signature1->setId('MF8xqL325bs7KiokMHTnHirF4go');
        $signature1->setKeyFingerprint(
            '880922DBEA733E906693E4A903CC890AFA1DAD4B');

        $signature1->setKeyId('03CC890AFA1DAD4B');
        $signature1->setCreationDate(1258220269);
        $signature1->setExpirationDate(0);
        $signature1->setValid(true);

        $userId1 = new Crypt_GPG_UserId();
        $userId1->setName('Second Keypair Test Key');
        $userId1->setComment('do not encrypt important data with this key');
        $userId1->setEmail('second-keypair@example.com');
        $signature1->setUserId($userId1);
        // }}}
        // {{{ signature2
        $signature2 = new Crypt_GPG_Signature();
        $signature2->setId('d0q7jibZpJSLpGAhNWhpSkZZeUg');
        $signature2->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature2->setKeyId('C097D9EC94C06363');
        $signature2->setCreationDate(1258220269);
        $signature2->setExpirationDate(0);
        $signature2->setValid(true);

        $userId2 = new Crypt_GPG_UserId();
        $userId2->setName('First Keypair Test Key');
        $userId2->setComment('do not encrypt important data with this key');
        $userId2->setEmail('first-keypair@example.com');
        $signature2->setUserId($userId2);
        // }}}

        $expectedMd5Sum  = 'f96267d87551ee09bfcac16921e351c1';
        $expectedResults = array(
            'data'       => null,
            'signatures' => array($signature1, $signature2)
        );

        $inputFilename  = $this->getDataFilename(
            'testDecryptVerifyFileDualSignatories.asc'
        );
        $outputFilename = $this->getTempFilename(
            'testDecryptVerifyFileDualSignatories.plain'
        );

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptVerifyFileDualOnePassphrase()

    /**
     * @group file
     */
    public function testDecryptVerifyFileDualOnePassphrase()
    {
        // {{{ signature
        $signature = new Crypt_GPG_Signature();
        $signature->setId('kgyLjfFigxOrliyc8XlS6NaLJuw');
        $signature->setKeyFingerprint(
            '8D2299D9C5C211128B32BBB0C097D9EC94C06363');

        $signature->setKeyId('C097D9EC94C06363');
        $signature->setCreationDate(1258220334);
        $signature->setExpirationDate(0);
        $signature->setValid(true);

        $userId = new Crypt_GPG_UserId();
        $userId->setName('First Keypair Test Key');
        $userId->setComment('do not encrypt important data with this key');
        $userId->setEmail('first-keypair@example.com');
        $signature->setUserId($userId);
        // }}}

        $expectedMd5Sum     = 'f96267d87551ee09bfcac16921e351c1';
        $expectedResults    = array(
            'data'       => null,
            'signatures' => array($signature)
        );

        $inputFilename  = $this->getDataFilename(
            'testDecryptVerifyFileDualOnePassphrase.asc'
        );
        $outputFilename = $this->getTempFilename(
            'testDecryptVerifyFileDualOnePassphrase.plain'
        );

        // decrypt with no-passphrase
        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );
        $this->gpg->clearDecryptKeys();
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        // decrypt with second key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );
        $this->gpg->clearDecryptKeys();
        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptVerifyFileNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group file
     */
    public function testDecryptVerifyFileNoDataException()
    {
        $filename = $this->getDataFilename('testFileEmpty.plain');
        $this->gpg->decryptAndVerifyFile($filename);
    }

    // }}}
    // {{{ testDecryptVerifyFileSignedOnly()

    /**
     * @group file
     */
    public function testDecryptVerifyFileSignedOnly()
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

        $expectedMd5Sum = 'f96267d87551ee09bfcac16921e351c1';
        $expectedResults    = array(
            'data'       => null,
            'signatures' => array($signature)
        );

        $inputFilename = $this->getDataFilename(
            'testVerifyFileNormalSignedData.asc'
        );

        $outputFilename = $this->getTempFilename(
            'testDecryptVerifyFileSignedData.plain'
        );

        $results = $this->gpg->decryptAndVerifyFile(
            $inputFilename,
            $outputFilename
        );

        $this->assertDecryptAndVerifyResultsEquals($expectedResults, $results);

        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
}

?>
