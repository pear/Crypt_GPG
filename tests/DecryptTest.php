<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Decryption tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit DecryptTestCase
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
 * @copyright 2005-2009 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * Base test case.
 */
require_once 'TestCase.php';

/**
 * Tests decryption abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class DecryptTestCase extends Crypt_GPG_TestCase
{
    // string
    // {{{ testDecrypt()

    /**
     * @group string
     */
    public function testDecrypt()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with first-keypair@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA5+T+RFnKO8SEAf/Z0WsgibKGysYfti9lfb2aY7vmAwCXnkrI8wZhqBAtfmB
oe16PinT47AtnXl4CUgB5jBJq32uzaZKFd/dyCzOog1P/87OB6aa2w5mfxJKIIXc
OevQgasWVSQw/1Ro90Fd/F9Q9fcHgHqCG2Q2BwkHG7IZ+V3zHlQpjj5flVTb7Te+
K5LM85t7kVEzc5vVzhMvoZluMA48YNL+g7qdA3oZDQ0rXRA1DnTVsQ74/RbIQaxZ
LUR7v05TVNrcwK/p2NFzLOJcYSkOYGUpks1qvfUlnsuh346SLHXmebif4GLkBB37
WWy69+2OwJhlE0qakEJZu2EMFRwRTOrplm9YPs8Z6QgAlqKh5+KoSZTGyzBI8dHv
lJJnlxBkzhrAj8g2kiUX5HfM+55jqtrdOo+PEd/nH56wTXaHqc7R0QE8ZdTyhmtd
hlyzhdu/bHm09Q5WVAWkaA5nVldEtwIhss+YiWc+Ieu+rd5QkQiW9OAc4B7ZvPCO
iDPpzT5rNe2hI4K9VkAKhcBDED+iCHkC4AZs3Rr/6tUCH+dY/roB0K1GtX2eYff6
UeeSRsyuYbwQkKZN6pC4JQFWW7z9semrTsHsQzE38EW0IxN8nGCiaAE5cxjtW7Pg
k9slzsranQ+n7teucg/+qlArY11LJmvPc7aoZoRCa76hzzDOHskA0/9GRcBQJlTd
ctJWAd9/Bk9NJkwWO+II22IQTWZZrRUN8FT6pnr/WxpWM8LL5nq1Lxf3SQX+H2Jq
JspFzixPnaDl16sE082GSg0VctFMkCZhb/jghMIQYJ2131DoGXJ4QDU=
=sjPP
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');

        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptNoPassphrase()

    /**
     * @group string
     */
    public function testDecryptNoPassphrase()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with no-passphrase@example.com
        // {{{ encrypted data no passphrase
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOAyS/OAcAwUtPEAf/cBqf/6najldCQzu5NNmuoyuujm2xpFESS4tljGhC7Hok
gqiUnknDJMwNjb80OhsHIQuWjUqaryktKH0Y+Q5s+oDwRQKVKxqeF8v4hYRq8tXc
a5gffr6lALBhpOHLcWM/oHQmPJgYAkdLDF1hoOwqlWGk5WklzjrRaJF2DwvvpvpL
8yEU1fuO9t7cnD27L466cGMrK473NdiO/Bsml4CL9biNzth5yMia6HmgRQ1VDPQ6
Q+plGSjTpCaXtq9fyK1Q+d9x/SeRqEVgo/R5n2w3YVZZxjNFPZ0wzMW0YtT7hTBc
AKPt5IEwVFlFkOUT+1Xq/wj5fOFzgV+n1EFMJyTaOgf9HSAm0/L2lymIkK0qEZZK
o0D0KBPQZrs47zj7qGnrmXlxkBydlwrCL6fULBVjK12ej4tdsYVROXfgkKohkEh4
OxEAX9OsQuf/pSJU6TIYF39TcfKB0FqbmsD6F0DN1hZ5wVdXl+8q92MyZu5a44zD
4fwKVlie+aENjiM0ePrDnFOK70KJVWoBlCXgouc3D6E7Rz4hC19WnWadOZF+2sHm
s7kI5xlIivsftziItjEqqQt74RYpo+TLHTwE3cKc9rXGgtEyD8xykugzHEwetbfd
fMdw+PvHv6jxBPdfz3/Xwe6kgqs1SrlOhQ/6tAf2uRD2C4LckXkc9Y4oC2T4iNlN
FNJWAepBEH0MkQvukbwwR9SQw2oTK2YyWFhLEFXcS61NCQP+du6IPLBNpeE1m+Mc
7lYaqPAkuwDq4wbJLEEVUyPNBnGRGD/al4cMowcGowGUEtn1kXR8lF4=
=aHiA
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group string
     */
    public function testDecryptKeyNotFoundException()
    {
        // was encrypted with missing-key@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA0l79YQdiRYDEAgAk66FL4HUw7X5PPL4wjDbt4Q68GRAeIdkQutLuGvnlCJ0
+LHt050deDhQd6FHmfT5K6Hp3eWApl87L5p0eQZhdaSguLZZxykFfhKENWua2YT4
Kb+EpOsZA3R8UTT9H/HHJ/K5DUl/Zyog+G7ddrKP7CMa9wyYxD6DOJ12b2Yn1cuA
u9am9eKmFZEwvoInF0WPdXeUyhMPY4QU43OUoIbF2fXjAq+WczqLbn0dDKH8CTqD
hVSFRxyqia+w5nCSnzzyAcICYFOKUWzn6EiBW95gfJNvi6KzMXI7XvaSHhEkYXKA
99WPLrHb95yRHjutXays+LDW00mjBttx40FhcQKdFgf/X8EhPdY+4F8hKctZ42FN
bw57qxV7dbalA4jC7lOaqcfvMa/y/pR3ewPN7CM5GWqXo0xrpB9uYlC+f3L2tQbI
5J/rYkCjQXZvOrpKaSCdp/7fhPp5NiFCy+VHakUfIou5O4KDm6h5lvFdFZtIFR9N
+9rL/C2WjBj6evbiBuGWjR9CrwvI57zYTjJgVSggwozwKwnse8R/8gUDyFLb26Dh
S/VKGm36N48kIuJ4UDUubLSJgwnU/Jiapx3M13GLsb/k+mjllwcc6/XlC0YN/7w4
ZvemnGWt6/ivt8NhRM7pRY4joJBtJNrAUsoijmscdWhhqnMqx8liUeEfSlrPStk0
INJWAaFpzdpNupyNLJI0pO0SAXX28yeNaDkJwzDZf8kU4U5T1zT+BabHVixmCB6/
CNl9/GMhmvFD5un2+hMDVfFjZ2FHSH5QgMF50Ws10+jpXan7PTDdNMw=
=Qe7y
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->decrypt($encryptedData);
    }

    // }}}
    // {{{ testDecryptNoDataException_invalid()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testDecryptNoDataException_invalid()
    {
        $encryptedData = 'Invalid OpenPGP data.';
        $this->gpg->decrypt($encryptedData);
    }

    // }}}
    // {{{ testDecryptNoDataException_empty()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group string
     */
    public function testDecryptNoDataException_empty()
    {
        $encryptedData = '';
        $this->gpg->decrypt($encryptedData);
    }

    // }}}
    // {{{ testDecryptBadPassphraseException_missing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testDecryptBadPassphraseException_missing()
    {
        // encrypted with first-keypair@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA5+T+RFnKO8SEAf/Z0WsgibKGysYfti9lfb2aY7vmAwCXnkrI8wZhqBAtfmB
oe16PinT47AtnXl4CUgB5jBJq32uzaZKFd/dyCzOog1P/87OB6aa2w5mfxJKIIXc
OevQgasWVSQw/1Ro90Fd/F9Q9fcHgHqCG2Q2BwkHG7IZ+V3zHlQpjj5flVTb7Te+
K5LM85t7kVEzc5vVzhMvoZluMA48YNL+g7qdA3oZDQ0rXRA1DnTVsQ74/RbIQaxZ
LUR7v05TVNrcwK/p2NFzLOJcYSkOYGUpks1qvfUlnsuh346SLHXmebif4GLkBB37
WWy69+2OwJhlE0qakEJZu2EMFRwRTOrplm9YPs8Z6QgAlqKh5+KoSZTGyzBI8dHv
lJJnlxBkzhrAj8g2kiUX5HfM+55jqtrdOo+PEd/nH56wTXaHqc7R0QE8ZdTyhmtd
hlyzhdu/bHm09Q5WVAWkaA5nVldEtwIhss+YiWc+Ieu+rd5QkQiW9OAc4B7ZvPCO
iDPpzT5rNe2hI4K9VkAKhcBDED+iCHkC4AZs3Rr/6tUCH+dY/roB0K1GtX2eYff6
UeeSRsyuYbwQkKZN6pC4JQFWW7z9semrTsHsQzE38EW0IxN8nGCiaAE5cxjtW7Pg
k9slzsranQ+n7teucg/+qlArY11LJmvPc7aoZoRCa76hzzDOHskA0/9GRcBQJlTd
ctJWAd9/Bk9NJkwWO+II22IQTWZZrRUN8FT6pnr/WxpWM8LL5nq1Lxf3SQX+H2Jq
JspFzixPnaDl16sE082GSg0VctFMkCZhb/jghMIQYJ2131DoGXJ4QDU=
=sjPP
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->decrypt($encryptedData);
    }

    // }}}
    // {{{ testDecryptBadPassphraseException_bad()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testDecryptBadPassphraseException_bad()
    {
        // encrypted with first-keypair@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA5+T+RFnKO8SEAf/Z0WsgibKGysYfti9lfb2aY7vmAwCXnkrI8wZhqBAtfmB
oe16PinT47AtnXl4CUgB5jBJq32uzaZKFd/dyCzOog1P/87OB6aa2w5mfxJKIIXc
OevQgasWVSQw/1Ro90Fd/F9Q9fcHgHqCG2Q2BwkHG7IZ+V3zHlQpjj5flVTb7Te+
K5LM85t7kVEzc5vVzhMvoZluMA48YNL+g7qdA3oZDQ0rXRA1DnTVsQ74/RbIQaxZ
LUR7v05TVNrcwK/p2NFzLOJcYSkOYGUpks1qvfUlnsuh346SLHXmebif4GLkBB37
WWy69+2OwJhlE0qakEJZu2EMFRwRTOrplm9YPs8Z6QgAlqKh5+KoSZTGyzBI8dHv
lJJnlxBkzhrAj8g2kiUX5HfM+55jqtrdOo+PEd/nH56wTXaHqc7R0QE8ZdTyhmtd
hlyzhdu/bHm09Q5WVAWkaA5nVldEtwIhss+YiWc+Ieu+rd5QkQiW9OAc4B7ZvPCO
iDPpzT5rNe2hI4K9VkAKhcBDED+iCHkC4AZs3Rr/6tUCH+dY/roB0K1GtX2eYff6
UeeSRsyuYbwQkKZN6pC4JQFWW7z9semrTsHsQzE38EW0IxN8nGCiaAE5cxjtW7Pg
k9slzsranQ+n7teucg/+qlArY11LJmvPc7aoZoRCa76hzzDOHskA0/9GRcBQJlTd
ctJWAd9/Bk9NJkwWO+II22IQTWZZrRUN8FT6pnr/WxpWM8LL5nq1Lxf3SQX+H2Jq
JspFzixPnaDl16sE082GSg0VctFMkCZhb/jghMIQYJ2131DoGXJ4QDU=
=sjPP
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('first-keypair@example.com', 'incorrect');
        $this->gpg->decrypt($encryptedData);
    }

    // }}}
    // {{{ testDecryptDual()

    /**
     * @group string
     */
    public function testDecryptDual()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

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

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->gpg->clearDecryptKeys();
        $this->assertEquals($expectedDecryptedData, $decryptedData);

        // decrypt with second key
        $this->gpg->addDecryptKey('second-keypair@example.com', 'test2');
        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->gpg->clearDecryptKeys();
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptDualOnePassphrase()

    /**
     * @group string
     */
    public function testDecryptDualOnePassphrase()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with both first-keypair@example.com and
        // no-passphrase@example.com
        // {{{ dual encrypted data one passphrase
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA5+T+RFnKO8SEAgAkvANavo5eEeJ/C0njcciAh/ELcgqynhwM4R3texCA9HF
043Z5kd4nMr2NUFBFG+UAzFSoB2zO5FZWsESMi71aIgzjX+CG754vw4j1I6Elsa8
An1Tldb4vPJqEWdp9ynu/i90wqYUc6DNp8MLilTfFk16GdPv2L8wjOUFlJqV3OdA
LJ68ppg3Qr8H0R81HSLPkSMc+o6GpljVShcejLeG14EpoW16ryZHXQk9T9bZzj1L
VQT/t8jgj5h2ocEtUCXixNBpFoRdMGMZB4SWXH4Aw3GiSCNSz/xQOgOSu9c/FdVD
WE1KCds4DGo5Za6rpDHxBCa8OhUNfhFiOAIcffz4MwgA07vc9jiAU7kGaR86AQuu
UlzYe0ZZd6hALVxUAfnBF2aG5Jjhm3muwOEu7e3zk3hd/xVPzT5BQ+1/mt+vlS8E
Ffjr13q/nKdoGTW7+orFjcwOmhpsJJcrTU+6TynkpmjNLyHhZix/roNbEPij7JJu
StO+vbyu22xWc2mp56AbhO8MLwBC6Vxc2h2ZJXjXcaCLkntnOEPxx653sC55KqHm
6gY4Ycwh+cnF9z+dWZBPak/LlHP4pmrSaeIc+8pS9Q6zFdVtrppzjTPCH0/FPxA2
QTwBMXrClF8iYNfvJ8a+Se3ZqzmPbpvbbdtTGm49Bo4FNrdHVkC+MMgBEQiJKkbq
/4UCDgMkvzgHAMFLTxAH/3a9Et2b3u61MMd0iag7haurrRsMwd6E9VD2SC6gbscF
efInr202g78bbyf0AnISnWBjZC8lfmiyoe6Ic7NO5HGzddJ2UPyeiA9ggNPlARlZ
OQngAaFzvP8NyMhYMIz5tUxxhYA9U8yjgEuhr/lq+olZwk6iiSaD3lP0q715XkLC
uVJ6uxZoBjRaKsVnNLcXvXY6C0IcrGzSr6wKvJm4kQ3RjahRjJvUJG8yeKtbUmHz
KBeorg4HQADXcK5Bcp9NCMatds1jvR/Zf8DakAO4G1T8Yb09xEQCVFqFIk7g1NDB
T/vHtAdYolvyeS7wlF1TMFuYfuMOi0kVdlbx/PlhpN4H/Recs7EMcl/9gUwUktOl
6xyDvA36QvO9RN0D504Ck+ZZjMNFId6fdU/ngSjq9AAteLRLUFgapbMTN2calf1J
0ehPzMINegvnVB2dR+xcc67QpxmR5uIA2jK1fSkhvOohE7UxE7xqp4SIMw6E92zy
ZvmhQVIqN6/s4k8KxrZKe/uhtDj963m7rsdR7v9wQsc1jJ/f+KZxy73r2Oz7BdTf
cpKaMKY/CHiy0NQ3jPrY3oVOIEzu15q4raOhIT5FQoH0pWgmBID3aQsEMjAdeCTy
JGHa4ZhQn9LSI+1XQmT3h8tWNYtAm9u3eqFsSm7ENMj3fY2Bd9wKlwTuTzsNhsdw
hvHSVgFkfzy/xAiLNPzXydzWJ3bm6ZetguDA/lNgfSaNVR4zSiPSbmV9ipJtrPpB
S6stCnUnw33F2IUOsEufvLFfEWtXY8qbBCULYC+no3GOwJhMyJQEI+xw
=1ZwO
-----END PGP MESSAGE-----

TEXT;
        // }}}

        // decrypt with no passphrase
        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->gpg->clearDecryptKeys();
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptDualNoPassphraseKeyMissing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group string
     */
    public function testDecryptDualNoPassphraseKeyMissing()
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

        $this->gpg->decrypt($encryptedData);
    }

    // }}}
    // {{{ testDecryptSignedData()

    /**
     * @group string
     */
    public function testDecryptSignedData()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // signed with first-keypair@example.com
        // {{{ signed data
        $signedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

owGbwMvMwCR4YPrNN1MOJCczrjFOEsrLL8pNzNEtzkzPS03RTUksSfS49JPJIzUn
J19HwTEnMzlVUcE9Pz8lqTJVR8EpP0mxw56ZlQGkBmaMIJO9GsOCo2L3pk5y2DNT
yiFKb0X03YSJqscaGRb0BKjZ3P+6SvjG160/WOa9vpey4QUDAA==
=wtCB
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $decryptedData = $this->gpg->decrypt($signedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptFirstSubKey()

    /**
     * @group string
     */
    public function testDecryptFirstSubKey()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with first subkey (ELG-E) of multiple-subkeys@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQIOA2+UGsw2JFPaEAf/TQ5We9V090WikWJTnpLwIZVgJSU1aCcG6R9h3wBOPFHi
RLQ4jBSL8EvXk4VwVJ0tuqpcB10+W1OugWbHTOxWnpbioEaUJk8jRu3MZvnyJe/d
3FcLlqXE0SocZR1Okxbp64tDvBzs4jjniQYfoMEM1j/VVlkQ02nufOLy6uvxPZjf
KkSeCVSy0HIaT0U5e3R28fT+dYN8i2RhT8AckjWeovJAMbHxCCsKdinI45u7O1QA
t9zZxMBaUvo/ikLM1/fyw7E8QaGCh4LlH8WrgBXneAgOPtlkHGziS/I54RSvGe07
yWrYkNzFch0l9RnGjAMqqzY9kXn+HxMr3bOFKeSzVQgAssvhcx6OjD+ZzRnVb8D+
i5KYFTrVih377e5cBhayWEEIdNeV/QTH9ooZxEVqxC10J5P6UgwNewOYhGJxr1yN
Nn2+KlgfoXuqa5RtLhShjDduPF5FS3v7HKGXuyXBQ+W9FcVeytayo8QRqbMqxWZe
dNlgjfbNsXJtUjm/48fYdmIiBkb5lf+2LPBhX9JHekVbzJdqx3kigcyXnh7VefKZ
fWnOmDdAd3hqeeagXUVGmtH+z6+XDGSKDuoBbwreHxr0ZIpW8mm6I6nx9kBF+LoE
OapSuua9s7ddcBxaOVUGECiH4owhHnfFQSz58XsRNIbkZL8R4YewrCmCoscN6/qN
adJWAY877iMazlpAzZWr6IZNvKqsET8yQbCllR0olqgh/VOmYUrnj31XtVFgP+47
kjHVkhz76aEUtquqMmWsR8r8p42TqR0u1KoW2dGysFzdPreXPORf3tQ=
=i9lR
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('multiple-subkeys@example.com', 'test');

        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptSecondSubKey()

    /**
     * @group string
     */
    public function testDecryptSecondSubKey()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with second subkey (RSA) of multiple-subkeys@example.com
        // {{{ encrypted data
        $encryptedData = <<<TEXT
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.4.6 (GNU/Linux)

hQEMAykh4NP/Ww9KAQf9HLxeXIXDMXEyJaCsfulZodSavNBP0IuZrXVkxrMPPart
fOf2N0Snnq3vA3MjPL9vEfD5sZLlA2bYMZmilyCh+lryYccME+Qa1gQ5xak1Cra1
y5ckZ7UNOTdHnhH5VvXk+bwm4KDbdeJJPLOxBJ/j6pf03vxeDEyoBPeeMzzzkXqH
+XZ9j7BHZcsLkY7j7iEw1DwcB4TdbOzkcVVBYwovCmhdY0i0m48mkqGVB0mKNUu+
YbJuOqiqjACIwXBelB4h/xEXGeEPk+ij1UMt74QhNM2OaQ2HUhIKYMWvAHYuGAvx
+ETuFiJo5OqCa4jW4Nqczw4FYLSDOVHdzKw7+dqeddJWAVST6k4823HSprJVFJ+i
pY9Bijx3ziDr14+IPxspoJTOInBFYihbwmLFL2RYsf0+pDFmngRhskWIyl4ann4/
w7YcziO6EF7lbOqYdn+rBA8e46kgbBQ=
=7fzo
-----END PGP MESSAGE-----

TEXT;
        // }}}

        $this->gpg->addDecryptKey('multiple-subkeys@example.com', 'test');

        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptFile()

    /**
     * @group file
     */
    public function testDecryptFile()
    {
        $expectedMd5Sum = 'f96267d87551ee09bfcac16921e351c1';
        $inputFilename  = $this->getDataFilename('testDecryptFile.asc');
        $outputFilename = $this->getTempFilename('testDecryptFile.plain');

        // file is encrypted with first-keypair@example.com
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptFile($inputFilename, $outputFilename);

        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptFileToString()

    /**
     * @group file
     */
    public function testDecryptFileToString()
    {
        $expectedData  = 'Hello, Alice! Goodbye, Bob!';
        $inputFilename = $this->getDataFilename('testDecryptFileToString.asc');

        // file is encrypted with first-keypair@example.com
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $decryptedData = $this->gpg->decryptFile($inputFilename);

        $this->assertEquals($expectedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptFileNoPassphrase()

    /**
     * @group file
     */
    public function testDecryptFileNoPassphrase()
    {
        $expectedMd5Sum = 'f96267d87551ee09bfcac16921e351c1';

        $inputFilename =
            $this->getDataFilename('testDecryptFileNoPassphrase.asc');

        $outputFilename =
            $this->getTempFilename('testDecryptFileNoPassphrase.plain');

        // file is encrypted with no-passphrase@example.com
        $this->gpg->decryptFile($inputFilename, $outputFilename);

        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptFileFileException_input()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testDecryptFileFileException_input()
    {
        // input file does not exist
        $inputFilename =
            $this->getDataFilename('testDecryptFileFileException_input.asc');

        $this->gpg->decryptFile($inputFilename);
    }

    // }}}
    // {{{ testDecryptFileFileException_output()

    /**
     * @expectedException Crypt_GPG_FileException
     *
     * @group file
     */
    public function testDecryptFileFileException_output()
    {
        // input file is encrypted with first-keypair@example.com
        // output file does not exist
        $inputFilename  = $this->getDataFilename('testDecryptFile.asc');
        $outputFilename = './non-existent' .
            '/testDecryptFileFileException_output.plain';

        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptFile($inputFilename, $outputFilename);
    }

    // }}}
    // {{{ testDecryptFileKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group file
     */
    public function testDecryptFileKeyNotFoundException()
    {
        // file is encrypted with missing-key@example.com
        $inputFilename =
            $this->getDataFilename('testDecryptFileKeyNotFoundException.asc');

        $outputFilename =
            $this->getTempFilename('testDecryptFileKeyNotFoundException.plain');

        $this->gpg->decryptFile($inputFilename, $outputFilename);
    }

    // }}}
    // {{{ testDecryptFileDual()

    /**
     * @group file
     */
    public function testDecryptFileDual()
    {
        $expectedMd5Sum = 'f96267d87551ee09bfcac16921e351c1';
        $inputFilename  = $this->getDataFilename('testDecryptFileDual.asc');
        $outputFilename = $this->getTempFilename('testDecryptFileDual.plain');

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptFile($inputFilename, $outputFilename);
        $this->gpg->clearDecryptKeys();
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        // decrypt with second key
        $this->gpg->addDecryptKey('second-keypair@example.com', 'test2');
        $this->gpg->decryptFile($inputFilename, $outputFilename);
        $this->gpg->clearDecryptKeys();
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptFileDualOnePassphrase()

    /**
     * @group file
     */
    public function testDecryptFileDualOnePassphrase()
    {
        $expectedMd5Sum = 'f96267d87551ee09bfcac16921e351c1';

        $inputFilename =
            $this->getDataFilename('testDecryptFileDualOnePassphrase.asc');

        $outputFilename =
            $this->getTempFilename('testDecryptFileDualOnePassphrase.plain');

        // decrypt with no-passphrase
        $this->gpg->decryptFile($inputFilename, $outputFilename);
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);

        // decrypt with first key
        $this->gpg->addDecryptKey('first-keypair@example.com', 'test1');
        $this->gpg->decryptFile($inputFilename, $outputFilename);
        $this->gpg->clearDecryptKeys();
        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
    // {{{ testDecryptFileNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group file
     */
    public function testDecryptFileNoDataException()
    {
        $filename = $this->getDataFilename('testFileEmpty.plain');
        $this->gpg->decryptFile($filename);
    }

    // }}}
    // {{{ testDecryptFileSignedData()

    /**
     * @group string
     */
    public function testDecryptFileSignedData()
    {
        $expectedMd5Sum = 'f96267d87551ee09bfcac16921e351c1';

        $inputFilename =
            $this->getDataFilename('testVerifyFileNormalSignedData.asc');

        $outputFilename =
            $this->getTempFilename('testDecryptFileSignedData.plain');

        $this->gpg->decryptFile($inputFilename, $outputFilename);

        $md5Sum = $this->getMd5Sum($outputFilename);
        $this->assertEquals($expectedMd5Sum, $md5Sum);
    }

    // }}}
}

?>
