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
abstract class Crypt_GPG_TestCase extends PHPUnit_Framework_TestCase
{
    // {{{ class constants

    const HOMEDIR = './test-keychain';

    const TEMPDIR = './temp-files';

    const DATADIR = './data-files';

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
        $pubringData = <<<TEXT
mQGiBEjS+M0RBADIuG1okbW2FPjlx1MKYthiN0rRcoN0P3H1G+0x6vMIV0YE
frHAJ7PQUo+cOYr1tAW8EquhUar/cAZSwRysMrYsQRggljxQKstToh36mcwt
dItIatGPSafkP7Y8tfPg/OG4n1LWvU/qc5qW0eUsrbtek3j3Ot96blZPPOki
+1p49wCg/NPaBcQz6fK6EwcI4M9icarEQJ0EAJdaVeJ1MOsBphcKkCQHtmId
uMQgmaJLidVJOl8tIXgAr6Hu2pGQkk7urGAzzzJ24jWzHJLqiEx/ex86sH1R
sHQctqcQhJU8YyYlO6e4R5nCdRiDYOAj1+rzogTTUpyngyQamTyAh7LnA/CC
MUOdwdduB4uCYsFF6VprJFy1FYx5A/9V/hpfeILigh/XVb3sWYdUyBRbxUoh
z25ItI7jkDLMlxN00w+IdUYEwl9bA8mmBf+q2BryLuoStg25krbC/KgEZbAT
EWhk+/A0j8nuEPn8A/Z8KqcLxFsCUwF690w7an/3WxAwVOumXhOKKEHosXkw
rS8AnfuIFq/atqy4EslP5bRgRmlyc3QgS2V5cGFpciBUZXN0IEtleSAoZG8g
bm90IGVuY3J5cHQgaW1wb3J0YW50IGRhdGEgd2l0aCB0aGlzIGtleSkgPGZp
cnN0LWtleXBhaXJAZXhhbXBsZS5jb20+iGAEExECACAFAkjS+M0CGwMGCwkI
BwMCBBUCCAMEFgIDAQIeAQIXgAAKCRDAl9nslMBjY2Y5AJ9vqmYB60lHF053
EC+ChvLNqrbxqwCfd7nMcmun0yeA7wt1KKdZExHz/niwAgADuQINBEjS+N0Q
CAD0p6PxTdTGFbABAA/KO8CkEqFYKfzu5gjB5jTK/awyrKYEp4KciexxnxGb
vVEg5M+C1Pg9NNFFwPDTl/HagLWqH8lMcKoFaXcz+Xfgwayuunu64/BXRsuK
AlQi0L6VzjUOaei3xCcEVv/ZqLQxM2uyOfyAysMVDT2BFIwf6qma09ttg0bp
L8eMt+dXBjBSyDWz5WC5gbgLX5B+VfQpnLL+DUvvh0qeHY9qmLYAca+qQnoj
956QRihzlNSjrlNrlyCYdXtFGfku91mA2PQghb5S7ifREiKH+6Iqk4FtioMq
rRko34u54yWMhfClRGtcmDb1ebp7yKIikljpQj6hkw9DAAMFB/4p8yiZuNwo
RFgJpRbLvOytac9iIlZs2mASMbABouqcUBLELqM+mOfmRgcJH2xFrmBJoIqB
ICUAkau3DR05oNkVTuFbtzIvNhxd5ES/2T45bAtqyHRDIvjwnr4ruN49h4FF
6jAeW+zFAnGeXXOOhdmWxxz7VGYXfmNHi5x1csx5KM4qEt+kiQ+KYPN7vsSE
PnuuO3OqyZ/pqZ2UQMtQAZ1bnLocgQ7GtBnSXCk2QgIg/sMgJoQVX5h8Ohvu
COCNkskBKmNzY7vfiG4JvGPG9RjyUpTJj2ewy0MoKYURhUXtnW7uMZ1T8OeB
/XtpBRRxGmmsm1aqabMi4MiXgh9lwikgiEkEGBECAAkFAkjS+N0CGwwACgkQ
wJfZ7JTAY2NeZQCg+HiigBkll6E00g9iWeO7jyDFEQUAn3ApGah7qCFj4YXN
1gZYqXhNEGb+sAIAA5kBogRI0vjdEQQA6muODLpYwTuvR3dsizYHVX76b+5/
uieTqwogt/P7I7/Kl0UakAu8znwdZj2TMpCZOwViii3LRYFSDeSJLXnGen2p
C9nLIGa6vfX0H4UNNhmQF5jbxQb99Dy6j1NvS+CbwCWfftKcfbnTriDGG1yE
o376R/w6CpBAYq8AHFfudcMAoJk5XtcR+6RDgKPHzsmORSR1V5uFA/9sVB2V
KcjginNKn39j6y2JHqISNrKP3AUsrXtxXFV7ZfYbSv2O9+g1xKqzYsOMJ5VU
/eicJI/Hr81HLpJj0o9ITCUuWnXaaoHQqlLUUroEDwQUjI1hJkWE2WK2xNTQ
cbhDj8JGzKSlC/z4IxqKo/0rlXHXYU4bwL8iEkOVeTEOOQP+PLuqQselyQr6
ia2LHcfcPicZgawCRA0S0voD8gx/XFBPsvMLOcs6/lrkMnhhVChwoJJDa+2Z
3/GrgmVqfrelOPfj9VtQZFjsZeqzI4hZ6CFv2F9zoZr+VXQe6IYtTG4CF8ta
R/5y8JJPy8pNSLLJZOovVqnWhqLqXAHhXth6d3K0YlNlY29uZCBLZXlwYWly
IFRlc3QgS2V5IChkbyBub3QgZW5jcnlwdCBpbXBvcnRhbnQgZGF0YSB3aXRo
IHRoaXMga2V5KSA8c2Vjb25kLWtleXBhaXJAZXhhbXBsZS5jb20+iGAEExEC
ACAFAkjS+N0CGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRADzIkK+h2t
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
p2ZC6a2/GIe2BP5mS6M9tDGfHluwAgAD

TEXT;
        // }}}
        // {{{ secring data
        $secringData = <<<TEXT
lQHhBEjS+M0RBADIuG1okbW2FPjlx1MKYthiN0rRcoN0P3H1G+0x6vMIV0YE
frHAJ7PQUo+cOYr1tAW8EquhUar/cAZSwRysMrYsQRggljxQKstToh36mcwt
dItIatGPSafkP7Y8tfPg/OG4n1LWvU/qc5qW0eUsrbtek3j3Ot96blZPPOki
+1p49wCg/NPaBcQz6fK6EwcI4M9icarEQJ0EAJdaVeJ1MOsBphcKkCQHtmId
uMQgmaJLidVJOl8tIXgAr6Hu2pGQkk7urGAzzzJ24jWzHJLqiEx/ex86sH1R
sHQctqcQhJU8YyYlO6e4R5nCdRiDYOAj1+rzogTTUpyngyQamTyAh7LnA/CC
MUOdwdduB4uCYsFF6VprJFy1FYx5A/9V/hpfeILigh/XVb3sWYdUyBRbxUoh
z25ItI7jkDLMlxN00w+IdUYEwl9bA8mmBf+q2BryLuoStg25krbC/KgEZbAT
EWhk+/A0j8nuEPn8A/Z8KqcLxFsCUwF690w7an/3WxAwVOumXhOKKEHosXkw
rS8AnfuIFq/atqy4EslP5f4DAwLxwn+n9mf1u2ArwjYd9+YzD/wWsQPS7Ia/
bH1duvwY/yIa2m2SVCsfoLLkpTRJmIbqjrA+0htB6IshuLRgRmlyc3QgS2V5
cGFpciBUZXN0IEtleSAoZG8gbm90IGVuY3J5cHQgaW1wb3J0YW50IGRhdGEg
d2l0aCB0aGlzIGtleSkgPGZpcnN0LWtleXBhaXJAZXhhbXBsZS5jb20+iGAE
ExECACAFAkjS+M0CGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAKCRDAl9ns
lMBjY2Y5AJ9vqmYB60lHF053EC+ChvLNqrbxqwCfd7nMcmun0yeA7wt1KKdZ
ExHz/niwAgAAnQJjBEjS+N0QCAD0p6PxTdTGFbABAA/KO8CkEqFYKfzu5gjB
5jTK/awyrKYEp4KciexxnxGbvVEg5M+C1Pg9NNFFwPDTl/HagLWqH8lMcKoF
aXcz+Xfgwayuunu64/BXRsuKAlQi0L6VzjUOaei3xCcEVv/ZqLQxM2uyOfyA
ysMVDT2BFIwf6qma09ttg0bpL8eMt+dXBjBSyDWz5WC5gbgLX5B+VfQpnLL+
DUvvh0qeHY9qmLYAca+qQnoj956QRihzlNSjrlNrlyCYdXtFGfku91mA2PQg
hb5S7ifREiKH+6Iqk4FtioMqrRko34u54yWMhfClRGtcmDb1ebp7yKIikljp
Qj6hkw9DAAMFB/4p8yiZuNwoRFgJpRbLvOytac9iIlZs2mASMbABouqcUBLE
LqM+mOfmRgcJH2xFrmBJoIqBICUAkau3DR05oNkVTuFbtzIvNhxd5ES/2T45
bAtqyHRDIvjwnr4ruN49h4FF6jAeW+zFAnGeXXOOhdmWxxz7VGYXfmNHi5x1
csx5KM4qEt+kiQ+KYPN7vsSEPnuuO3OqyZ/pqZ2UQMtQAZ1bnLocgQ7GtBnS
XCk2QgIg/sMgJoQVX5h8OhvuCOCNkskBKmNzY7vfiG4JvGPG9RjyUpTJj2ew
y0MoKYURhUXtnW7uMZ1T8OeB/XtpBRRxGmmsm1aqabMi4MiXgh9lwikg/gMD
AvHCf6f2Z/W7YB9YTXxKPJp6zbmhmsBCAQIHNuufQtJKmUtVc3IZC06Ip8pa
19eytbzqRG7JkectW2YtFpdi7g61Aw4RynmsNoScsEsolN5WhsGISQQYEQIA
CQUCSNL43QIbDAAKCRDAl9nslMBjY15lAKCMiOSsamO0x8emnFVM3EVS4XUa
9ACfbJ9okoKrn7a/uEOVWfxWTvdeQxGwAgAAlQHhBEjS+N0RBADqa44MuljB
O69Hd2yLNgdVfvpv7n+6J5OrCiC38/sjv8qXRRqQC7zOfB1mPZMykJk7BWKK
LctFgVIN5IktecZ6fakL2csgZrq99fQfhQ02GZAXmNvFBv30PLqPU29L4JvA
JZ9+0px9udOuIMYbXISjfvpH/DoKkEBirwAcV+51wwCgmTle1xH7pEOAo8fO
yY5FJHVXm4UD/2xUHZUpyOCKc0qff2PrLYkeohI2so/cBSyte3FcVXtl9htK
/Y736DXEqrNiw4wnlVT96Jwkj8evzUcukmPSj0hMJS5addpqgdCqUtRSugQP
BBSMjWEmRYTZYrbE1NBxuEOPwkbMpKUL/PgjGoqj/SuVcddhThvAvyISQ5V5
MQ45A/48u6pCx6XJCvqJrYsdx9w+JxmBrAJEDRLS+gPyDH9cUE+y8ws5yzr+
WuQyeGFUKHCgkkNr7Znf8auCZWp+t6U49+P1W1BkWOxl6rMjiFnoIW/YX3Oh
mv5VdB7ohi1MbgIXy1pH/nLwkk/Lyk1Isslk6i9WqdaGoupcAeFe2Hp3cv4D
AwLv5LBCOJTgDGCxp17xpdBgHR0gEyiAn0M+oX2mbSUGjJLJ0FHlt4V4mvY4
sj+zEuh0y7jOnVnhAK/ny7RiU2Vjb25kIEtleXBhaXIgVGVzdCBLZXkgKGRv
IG5vdCBlbmNyeXB0IGltcG9ydGFudCBkYXRhIHdpdGggdGhpcyBrZXkpIDxz
ZWNvbmQta2V5cGFpckBleGFtcGxlLmNvbT6IYAQTEQIAIAUCSNL43QIbAwYL
CQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEAPMiQr6Ha1LoAEAn2/+fh/OQz6P
XG9zBLcrJFf3P8xmAKCCfBjWSB+HPeJr5Fn5MJF4uCnjfbACAACdAmMESNL4
4RAIAOSLYQiKvFjlNQjrParMESl5JMtbJmyUQKBqQlMTJuvomKddA4REq6qX
a24Of+WUqIKxh/jAwgfXs58D3YYWgv2aX6q6lUgKhcLqAIVTZfRFDn6R+JCO
isq178se5UMP2g91/UR9mSuM/HKm4ogcS+hXPd4yD+AhHbzUZgPnWZbyJ/HR
t7XWU+Cy69L94nHDMQbfYpBi6d1a4dO683NG3YJXtrlI4K/Q09euXfFHeqoc
yHnh4eJRSOHXyJqarwlNM/YTj1dWmgFbJ68NySONOrUEL4jyd4ubb4oNmQnT
GpQvmJKocQtRvTxKAFZ7aB5veVKVTJNzyjO5vPRJWgw1EzsAAwUH/1S9DkTg
FctOb0YsOeOtKmYnFzVxjQNGbBjaMhNHDTXvgxHGdWY6h7uyl/+cnPNoCcc+
sUl4Ob5ogE3BNLAOsg4TyuvnYAF8GEk9EenCTDngepd+L4K5L4lq8Be+cWgF
s9vVhXCP9d0CSzo/3FpJ5WqsIqk01U5QKze4iWvG1qVK5vJWEe/33A7JFHZf
+rW95nlJewyqeDAKFluJA0Usbx1FcfTwbMicJjL7GrQoYHfTqW0RQL3XIiMN
dRoBVuK9CL1LtSxibfg+0aokak4SeQXbtu/kMydLfBREw8fKFrgSmJSxOKD6
2J6J+U5am8qvQ/njqIAk6YA3xvcHd/IU7g7+AwMC7+SwQjiU4AxglRNFH8ZQ
L+7gJFaH8bEhjkocpbjCI/0PlsTz72zonwHtCRyH7XmjzgzOELQGGUa4scWF
cKUBwyWsfqbjGpLRUSO8wAvjWlRT64hJBBgRAgAJBQJI0vjhAhsMAAoJEAPM
iQr6Ha1LLvoAnjf02AwIP4uMSl2HpSIh7QaO0xqOAJ4gyr9pHEV1c/kebV8K
VrcS51e45bACAACVAbsESNL46REEALKfbQFXnz7HRzYWrj1Mu2tZAEJP1XGc
114JQniwSCiZMRSFhe4sAntSY5HCOFPXqXZfsQkpdkR8Rt9kjyP+JiekgGn+
Ji2xnzLps3vTB142lG1mQHcK7WZTkLp3+2HDROZ51b3dtDTrAy3MEQ8RC44z
5iOIpBmOOCoWaWflPdy3AKDpv8fz//eMRrY3knxTjJM7FmPFQwP9E5f+60sM
0pf51MvLr25CuWv3i1pvCzOkGB1NgzDOB5+BRgN1Ht6xYzmtnkwwlf2U/N54
8w9/T/tGWWFgDheAnsS/NVMY0C4vjktUmsb0Hl2HCsKGgoU1S0J8g1LrW6s9
2FRADxjOZTEj6IOAGQPgW6MuiHzDD6nG6klGxhlvf2ID/Rkkpk54g3cnJSsi
WpKoQ0bnj0fT5jhMLm3xiLFp8Hx88GOUzPT7EYxHdfFvxYcP5cV26Wv+xVnh
ZnTRi04aFL/dkXuoavEIIGsICMNF0/OpoXXmcxqqAiiA4g4vmP3AjrBGkywk
HERu21ZH/0rgFeEGuLCD2q/i9qbDMUzS3a8tAACdF7M7MkLEzAfEkc/XDqGk
TwRBdXYJerRzTm8gUGFzc3BocmFzZSBQdWJsaWMgYW5kIFByaXZhdGUgVGVz
dCBLZXkgKGRvIG5vdCBlbmNyeXB0IGltcG9ydGFudCBkYXRhIHdpdGggdGhp
cyBrZXkpIDxuby1wYXNzcGhyYXNlQGV4YW1wbGUuY29tPohgBBMRAgAgBQJI
0vjpAhsDBgsJCAcDAgQVAggDBBYCAwECHgECF4AACgkQlFY/s5itprImZwCg
w0cEkPaPI3fPfc2h5Z6j4TyuHSYAn0ZgHrSM914DLxAjwd5wbXlt3uQBsAIA
AJ0CPQRI0vj1EAgAhewinC9zCUsdDq6ajNdMztkTKyuhZuNB/7a0xBWuS2ug
UobAEU549c7BuUYw8B9qpW1krb5ZDOa/szWN6FkWoyJwKG6POp38bASCZ0JL
3QLcrSEENjdmqsjWggQEwfFaTeb15PLEPJQW1m5WgD31Cf5HCBRQmPMgsI2r
9XDiLFJm8BdJ6JTtV9UHwCbM/kA7U3RrL30uVfreJYhPepQvjkfU66ZzHADj
mpu2d8iMee1I7d581NecYG9U87LZf2Xr9r2m4YmiGO5w/oKVyMXuJfNAgMSM
u9EIF+whBFdQjlZ2nEfwf0K1oU/Eod1lKTRAFYcpDlwhO5M18pIcc4gI+wAD
BQf/d5ISDTDuirgkyFOi1sJxk/avD10NNvmaXYxc2gTYF7Natkq0T0x2behW
wNbO3DhZOFrZqlj+mkg9LRx/Q0XMviac1X0ils20MdS2PSa8wkg8BC+2RVbV
6DrNAyF+E2+9penGulTgKsPIybn0azBgVkfoRBjpTu8D8xFH+ASaZUt+850o
ynFlDmAXWfqU5pcTMVEny+KrY62S6TDH2zLEfIJKK97oRuU9F86AUbAIn575
fUHJnzgEoelxKJTWWlDCH9IPq37ZrStNeOBqURgzttvMaL7/zhcVPIEw9WFg
G8TCEpYNOg+x0gqETHM2rIRBdGfjgaSY7T9fXoxiikv37AABVAg+anwLssMt
ypICzst26P2lLSCGT1f7icmHvSqBgVdOQizx/9QYGMoUigAUyohJBBgRAgAJ
BQJI0vj1AhsMAAoJEJRWP7OYraaywmQAoK31UjQ8v0JxjEBYQISdvYuLNpA8
AKC7QxpJWOad2BFLoSh6WM3H7KvMUrACAAA=

TEXT;
        // }}}
        // {{{ trustdb data
        $trustdbData = <<<TEXT
AWdwZwMDAQUBAAAASNPRRgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAJAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAqAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAALwAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAmAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAKAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAoAAAAAAAAAACwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADACNIpnZxcIREosyu7DA
l9nslMBjYwYAAAAAAAAfAAAAAAAAAAAAAA0ASuRA053T81XR0YsL9GQz36zO
so8GAAAAAAAAAAAAAAAAAAAAAAAMAIgJItvqcz6QZpPkqQPMiQr6Ha1LBgAA
AAAAACEAAAAAAAAAAAAADQDkLyWSxvRVinJea5Y3Sc4dh3lKQQYAAAAAAAAA
AAAAAAAAAAAAAAwA+DEYy29YktwcPpNtq6ge9U6MDesGAAAAAAAAIwAAAAAA
AAAAAAANAMR3BlsMercywmS8VQx+WBRwzSxrBgAAAAAAAAAAAAAAAAAAAAAA
DAAeycXb8jndCjpPzQ2UVj+zmK2msgYAAAAAAAAlAAAAAAAAAAAAAA0A+Xih
okzxb5YYF2H8zt6XjTHnb5oGAAAAAAAAAAAAAAAAAAAAAAAMAJSPmDX/CfX5
HP8qwSaKtxA0NeZdAAAAAAAAACcAAAAAAAAAAAAADQB1TeCPc5cRDuwveD0X
xhsm64ZrYAAAAAAAAAAAAAAAAAAAAAAAAAwAxo3/oHXKbdbf3Wfe8oOFM8Yg
1NUAAAAAAAAAKQAAAAAAAAAAAAANAOQflEprmQfxXYoQ4ziqhrc8pjZDAAAA
AAAAAAAAAAAAAAAAAAAADAAlEjmrDfswlGd8hOOp7mR+yD1FcwAAAAAAAAAr
AAAAAAAAAAAAAA0A5B+USmuZB/FdihDjOKqGtzymNkMAAAAAAAAAAAAAAAAA
AAAAAAAMANk0YYDRuuh0Qo8Qx/Ye3VqwpH+AAAAAAAAAAC0AAAAAAAAAAAAA
DQDkH5RKa5kH8V2KEOM4qoa3PKY2QwAAAAAAAAAAAAAAAAAAAAAAAAwAjfos
sg2v7kfmnu1bCuJ9bDb23VAAAAAAAAAAMAAAAAAAAAAAAAALAAAAAAAAAAAe
AAAALgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQDkH5RKa5kH8V2KEOM4
qoa3PKY2QwAAAAAAAAAAAAAAAAAAAAAAAA==

TEXT;
        // }}}
        // {{{ random_seed data
        $randomSeedData = <<<TEXT
U7K0I8d0zMCCC7+rIilY9ntdKFHXJjI35LH5kwwCp9ZBFHgvnc3XZ7FVU5/5
EUM48uu7TQEF/3UOt1iQcJgCXJJsldZfa2U3S98CX6K/8TeWOdV4JByen2Bi
4dD2yFfkJ8Uyj27RjFE5vs8g9AM8ubLiXAuX/CkVPfb1xyGC2tgOvklr0jGT
s00i3hchbmAZG24ol+P4MI/WQAPTneypqGzJf3Tsepw6L5O7Etd9He2pAzYs
uKkVzWpmYbFBAz7zYYEnnqzhlICNP2XE0MCiVSFT3czI5v8Q4nH4OVCsVysI
NKoP/axLGvdd2XbOXd2UJ0+OoqxBSI3ohGGXNV3MPeVocHFK/vBpDy8+tLPF
PtBmMP5vPTgIY4ASKA2NftgLcQTy6An+76kVGcKPkYSAMNiq10fLXeHCAxH0
pfeN2UH9ukK1K78WV3Q+/o6lKztEjivDGyZ6cU5jgWkI7GMJ7el91DtjdLe0
UZyUl18czXV+fTthZpGHxVQWGLdZDxl7ALr+NsMIi0AOIUcHs2eqROAMHM4w
wFBsMS/FwDZ8laPPYQjK8j/UzY0wcPb4JA5RbfOehzrUzLhOXTrVFqZJdsOI
DWaXr38e9YFixKsSta2Sf+61diKqhHDEePanGsy/f19Xj0KrVnkx/C8gRF0d
7lOrVi0LgB+I5fNbRVl7HLS95/OE7aTjcDJ/Gv6OxJW0sYCkVDq3ovl8dyLp
Lx/qT+3Rkg5h6y1kJ5QgnDC8ZTBXC46aJfARTY0wP1a4Dm445eAiVWorOf2r
P++wDnCxNUsUWr7WikOt

TEXT;
        // }}}

        mkdir(self::HOMEDIR);

        $pubring = fopen(self::HOMEDIR . '/pubring.gpg', 'wb');
        fwrite($pubring, base64_decode(str_replace("\n", '', $pubringData)));
        fclose($pubring);

        $secring = fopen(self::HOMEDIR . '/secring.gpg', 'wb');
        fwrite($secring, base64_decode(str_replace("\n", '', $secringData)));
        fclose($secring);

        $trustdb = fopen(self::HOMEDIR . '/trustdb.gpg', 'wb');
        fwrite($trustdb, base64_decode(str_replace("\n", '', $trustdbData)));
        fclose($trustdb);

        $randomSeed = fopen(self::HOMEDIR . '/random_seed', 'wb');
        fwrite($randomSeed, base64_decode(
            str_replace("\n", '', $randomSeedData)));

        fclose($randomSeed);

        mkdir(self::TEMPDIR);

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

        // remove temporary files and temporary directory
        $iterator = new DirectoryIterator(self::TEMPDIR);
        foreach ($iterator as $file) {
            if (!$file->isDot()) {
                unlink(self::TEMPDIR. '/' . $file->getFilename());
            }
        }

        rmdir(self::TEMPDIR);
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

    // file related helper methods
    // {{{ getMd5Sum()

    protected function getMd5Sum($filename)
    {
        if (`which md5sum` == '') {
            $this->markTestSkipped('md5sum not available. Cannot verify ' .
                'files for file tests.');
        }

        $sum = explode(' ', `md5sum $filename`);
        $sum = $sum[0];
        return $sum;
    }

    // }}}
    // {{{ getDataFilename()

    protected function getDataFilename($filename)
    {
        return self::DATADIR . '/' . $filename;
    }

    // }}}
    // {{{ getTempFilename()

    protected function getTempFilename($filename)
    {
        return self::TEMPDIR . '/' . $filename;
    }

    // }}}
}

?>
