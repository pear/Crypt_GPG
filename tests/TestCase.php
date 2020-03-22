<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * PHPUnit AllTests suite for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.6 or greater package to be installed.
 * PHPUnit is installable using PEAR. See the
 * {@link http://www.phpunit.de/manual/3.6/en/installation.html manual}
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
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/>
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2013 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

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
 * 1) first-keypair@example.com - passphrase 'test1'
 *    A public-private key pair that can be used to both encrypt and decrypt.
 *
 * 2) second-keypair@example.com - passphrase 'test2'
 *    A public-private key pair that can be used to both encrypt and decrypt.
 *
 * 3) public-only@example.com - passphrase 'test'
 *    A public key with no private key. Used for testing private key import.
 *
 * 4) no-passphrase@example.com - no passphrase
 *    A public-private key pair that can be used to both encrypt and decrypt
 *    with no passphrase.
 *
 * 5) external-public@example.com - passphrase 'test'
 *    A public key that does not initially exist in the keyring that can be
 *    imported.
 *
 * 6) multiple-subkeys@example.com - passphrases 'test1' and 'test2'
 *    A public-private key pair that has multiple encrypting subkeys. The
 *    first subkey is an ELG-E key. The second is an RSA key.
 */
abstract class Crypt_GPG_TestCase extends PHPUnit\Framework\TestCase
{
    // {{{ class constants

    const HOMEDIR = 'test-keychain';

    const TEMPDIR = 'temp-files';

    const DATADIR = 'data-files';

    // }}}
    // {{{ protected properties

    protected $gpg;

    // }}}
    // {{{ getOptions()

    protected function getOptions()
    {
        $config = array(
            'homedir' => __DIR__ . '/' . self::HOMEDIR,
//            'binary' => '/usr/bin/gpg2',
//            'agent'  => '/usr/bin/gpg-agent',
//            'gpgconf'  => '/usr/local/bin/gpgconf',
//            'cipher-algo' => 'AES256',
//            'digest-algo' => 'SHA512',
//            'compress-algo' => 'zip',
//            'debug'  => true,
//            'options' => array(),
        );

        if ($binary = getenv('TESTS_GPG_BINARY')) {
            $config['binary'] = $binary;
        }

        return $config;
    }

    // }}}

    // set up
    // {{{ setUp()

    public function setUp()
    {
        // load test configuration file if it exists
        $configFilename = __DIR__ . '/config.php';
        if (file_exists($configFilename)) {
            include $configFilename;

            if (   !isset($GLOBALS['Crypt_GPG_Unittest_Config'])
                || !is_array($GLOBALS['Crypt_GPG_Unittest_Config'])
            ) {
                $this->markTestSkipped(
                    'Unit test configuration is incorrect. Please read the '
                    . 'documentation in TestCase.php and fix the '
                    . 'configuration file. See the configuration in '
                    . '\'config.php.dist\' for an example.'
                );
            }

            $this->config = $GLOBALS['Crypt_GPG_Unittest_Config'];
        } else {
            $this->config = array();
        }

        // default test config values
        if (!isset($this->config['enable-key-generation'])) {
            $this->config['enable-key-generation'] = false;
        }

        $this->_setUpKeyring();
        $this->_setUpTempdir();

        $this->gpg = new Crypt_GPG($this->getOptions());
    }

    // }}}
    // {{{ _setUpKeyring()

    private function _setUpKeyring()
    {
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
S6ABAJ9v/n4fzkM+j1xvcwS3KyRX9z/MZgCggnwY1kgfhz3ia+RZ+TCReLgp
432wAgADuQINBEjS+OEQCADki2EIirxY5TUI6z2qzBEpeSTLWyZslECgakJT
Eybr6JinXQOERKuql2tuDn/llKiCsYf4wMIH17OfA92GFoL9ml+qupVICoXC
6gCFU2X0RQ5+kfiQjorKte/LHuVDD9oPdf1EfZkrjPxypuKIHEvoVz3eMg/g
IR281GYD51mW8ifx0be11lPgsuvS/eJxwzEG32KQYundWuHTuvNzRt2CV7a5
SOCv0NPXrl3xR3qqHMh54eHiUUjh18iamq8JTTP2E49XVpoBWyevDckjjTq1
BC+I8neLm2+KDZkJ0xqUL5iSqHELUb08SgBWe2geb3lSlUyTc8ozubz0SVoM
NRM7AAMFB/9UvQ5E4BXLTm9GLDnjrSpmJxc1cY0DRmwY2jITRw0174MRxnVm
Ooe7spf/nJzzaAnHPrFJeDm+aIBNwTSwDrIOE8rr52ABfBhJPRHpwkw54HqX
fi+CuS+JavAXvnFoBbPb1YVwj/XdAks6P9xaSeVqrCKpNNVOUCs3uIlrxtal
SubyVhHv99wOyRR2X/q1veZ5SXsMqngwChZbiQNFLG8dRXH08GzInCYy+xq0
KGB306ltEUC91yIjDXUaAVbivQi9S7UsYm34PtGqJGpOEnkF27bv5DMnS3wU
RMPHyha4EpiUsTig+tieiflOWpvKr0P546iAJOmAN8b3B3fyFO4OiEkEGBEC
AAkFAkjS+OECGwwACgkQA8yJCvodrUsu+gCfZEfLQC9nxeeMQiTwAoAQoork
GE8An3OSljAgQACg/b7LvUpWPH7GjtjSsAIAA5kBogRI0vjiEQQAj5dNt6fo
yJ1olLXO80gVNQ+Jr+Ns0jsD3Qt+z5/+MfRcoSDlxCwkU6bJwMPa0+kdwbwA
uLjuvH8Y8RQsE6bGutEbB8OG8KUgGLn9LeV4PhkCK4rZZlx1WMJLtx5IeEr7
9KrnpqKBrifZS8CB2nC/+FtXUxywdq86J9E+JMexMWcAoP1ypUQ/c2250DoI
59BGkvH3EpvhA/9SDH5As+WnPWN4wVJXAKzmXDpU688bLfojGZuH9H4fHRQg
mkTdImlS0nQjWhb2ymyWGWndcN4xQDFPW1/N35aoFdcDDzvzXp3zInQSKrCs
4LbWkKOVZo1j7cMjiVzg0dpRykEdoRQpCCpRzDy1d2sAhlfIk8ok2TCYq3bb
37NuqAP/Uk2K6Psgfcqx7n3X4zNbvEm0iISuo1KKtmoyzx2ixdp0WWcr9YJ5
M0RXfv1cXMenMKfEHei+M/tLFN6TEuF/K7dr6opStprINVax54xoBSH5nyL2
ORJq4TcxMel/Nn20fX/JcC8uTf4D5t9untMUsNa1nUdeVbpCT25iup3/6S+0
XFB1YmxpYyBPbmx5IFRlc3QgS2V5IChkbyBub3QgZW5jcnlwdCBpbXBvcnRh
bnQgZGF0YSB3aXRoIHRoaXMga2V5KSA8cHVibGljLW9ubHlAZXhhbXBsZS5j
b20+iGAEExECACAFAkjS+OICGwMGCwkIBwMCBBUCCAMEFgIDAQIeAQIXgAAK
CRCrqB71TowN6/A2AJ9fw6xeY8N9T9y+jJVnXpS7keDzpwCfSLeyMp3yWpWC
B6AFrWNsZJE7E/qwAgADuQINBEjS+OgQCACnrlHnvwSzyq0BIMCAhth8mUlP
Ayi8ScDgonr2alW3ebNwVYy0kK+6KW/BJBD5V8rGN6a1t78hsx72yyPidNIv
D+bB5QHz21GPxnNpL7/3fXYBLytr/EgOvqRNJ8pxEqNeAzOQn4DXetjAbksV
afK6aDfrGCWbNcqF5wSRFU99afchKirfOKtmVA5Zwph3IDZnrzlIokL837ed
Soo4nuqsDt5PrTwsWSzK0Ed4581/mbsILjAATdEDP5mQm9ZFsTYbmlRqVmS2
ry4oxPlZCC+4U/eGe+S7nKKWmjYQtOdiQ7eW1zc0cJz2/6OGKRrI+vtG9R1U
9tohNPzTJgoE/KALAAMGCACnNHW9b9+/Oas7mlbMC93i6ZWH9infife9bJcy
74kgcDuzTyuRPOUxfNqYgJCaSPAC4LAm3S3sEDbwufKCiHaOjGjy0T86jAWT
4jNt4DZWvPvV39PlIwO0LaZ48TSbduYI4sGxy7lokh+CLVf9/Ovjh/iL7qGp
UMK446adW1svjEEGdLopd1xY/tBtWHEbdKkf0CB39Be9JCbQ5vP2IpnXUURf
OCdVkZdoIzQYGwUT0m41jn6GLoDvatxyOELRXULLje954iE4T6/ekrRr8EZS
WANJ2BWikT3NRJDDO6jztRtjcSgNYGoNFJEJEx+a/xLZv1UkhE90I4dkYIhH
j3/RiEkEGBECAAkFAkjS+OgCGwwACgkQq6ge9U6MDes2wACglTZ6U7J87L1I
J2z50EaPAfUfz5kAoMItiWMqx9kgL7JJWsTaCTBBL2CSsAIAA5kBogRI0vjp
EQQAsp9tAVefPsdHNhauPUy7a1kAQk/VcZzXXglCeLBIKJkxFIWF7iwCe1Jj
kcI4U9epdl+xCSl2RHxG32SPI/4mJ6SAaf4mLbGfMumze9MHXjaUbWZAdwrt
ZlOQunf7YcNE5nnVvd20NOsDLcwRDxELjjPmI4ikGY44KhZpZ+U93LcAoOm/
x/P/94xGtjeSfFOMkzsWY8VDA/0Tl/7rSwzSl/nUy8uvbkK5a/eLWm8LM6QY
HU2DMM4Hn4FGA3Ue3rFjOa2eTDCV/ZT83njzD39P+0ZZYWAOF4CexL81UxjQ
Li+OS1SaxvQeXYcKwoaChTVLQnyDUutbqz3YVEAPGM5lMSPog4AZA+Bboy6I
fMMPqcbqSUbGGW9/YgP9GSSmTniDdyclKyJakqhDRuePR9PmOEwubfGIsWnw
fHzwY5TM9PsRjEd18W/Fhw/lxXbpa/7FWeFmdNGLThoUv92Re6hq8QggawgI
w0XT86mhdeZzGqoCKIDiDi+Y/cCOsEaTLCQcRG7bVkf/SuAV4Qa4sIPar+L2
psMxTNLdry20c05vIFBhc3NwaHJhc2UgUHVibGljIGFuZCBQcml2YXRlIFRl
c3QgS2V5IChkbyBub3QgZW5jcnlwdCBpbXBvcnRhbnQgZGF0YSB3aXRoIHRo
aXMga2V5KSA8bm8tcGFzc3BocmFzZUBleGFtcGxlLmNvbT6IYAQTEQIAIAUC
SNL46QIbAwYLCQgHAwIEFQIIAwQWAgMBAh4BAheAAAoJEJRWP7OYraayJmcA
oMNHBJD2jyN3z33NoeWeo+E8rh0mAJ9GYB60jPdeAy8QI8HecG15bd7kAbAC
AAO5Ag0ESNL49RAIAIXsIpwvcwlLHQ6umozXTM7ZEysroWbjQf+2tMQVrktr
oFKGwBFOePXOwblGMPAfaqVtZK2+WQzmv7M1jehZFqMicChujzqd/GwEgmdC
S90C3K0hBDY3ZqrI1oIEBMHxWk3m9eTyxDyUFtZuVoA99Qn+RwgUUJjzILCN
q/Vw4ixSZvAXSeiU7VfVB8AmzP5AO1N0ay99LlX63iWIT3qUL45H1OumcxwA
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
2SXgmRBMkfID6VoR87RDD/RHSbACAAM=

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
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
Q/q3S7ACAAA=

TEXT;
        // }}}
        // {{{ trustdb data
        $trustdbData = <<<TEXT
AWdwZwMDAQUBAAAASXgQ5QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoAAAAA
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
AAAAAAAAAAAAAAoAAAAAAAAAACwAAAAAAAAAAAAAAAAAAAAxAAAAAAAAAAAA
AAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
CgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAMwAAAAAAAAAAAAAKAAAAAAAAAAAA
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
qoa3PKY2QwAAAAAAAAAAAAAAAAAAAAAAAAwA3Z5wduQspEtWG5gn+7R5kNtT
j/cAAAAAAAAAMgAAAAAAAAAAAAANADPMTOwYcVpigI8JYuYIOyOWVB6sAAAA
AAAAAAAAAAAAAAAAAAAADAD53yG10t0C0992AnCwemIdySlXZQYAAAAAAAA0
AAAAAAAAAAAAAA0AM8xM7BhxWmKAjwli5gg7I5ZUHqwGAAAAAAAAAAAAAAAA
AAAAAAA=

TEXT;
        // }}}
        // {{{ random_seed data
        $randomSeedData = <<<TEXT
neyWWNvenulSaxVyMeIGkfDEfjYOk/fWdXdVziAlyCuTOaA3TQ3CKgFyUMCl
56z9k4gvoAVk4UKpspxvt0yvPh10wejwkb7MrFQ58f9mqSdhSxnP06dmxPaA
pmjTVaHQ74o7U/sitSM9DgCR/sKwmm7SFqP8LhELgHaIfx1AWbHNuTCSYdxH
z4SMMzTAiMq6cMKv86cpjAWMLABM5TFFKZzYtj+lpSowcuNkHWBU6qv7Y8Iw
ZMvcXX8cCvFWLVY9JNfQPvbb3WONrWmkqfExqAe2zKRyYUVP9mY9szAWwP0k
HqR1fICVuGVzJEzz//7AukOJ1TNiokgPoSW7KayJ1YjTuGyQc4JOOxvEdZAR
uXdEmD8V3yhQ/bN86OocZi/gT5+2Qorbk19hlHVAd4xw6HhFgBiqM0snhnQq
2YJOeVWuciAlnyetCV5DaOI5mUKhNOqT2EUo1qQ6vI9uZ8n+aJxD4DPH+AHo
wOzWzzsQujmaLmzulJtZnvHpwm/Sbi0qG9sohnxAD8INhnbRSviwROBgAR1r
HzticUERCJ6C+RGSUqa0YktAzNY5yZiyWEhPJfl16zC4vNFOdJmjWlf01ugJ
l7FlURvzHb3BkLJVlNCYNBRvW0yz2xXrhOzc1Nl5cpYGl3IWxopQDpHLHXYl
DVEKIlTgEQHq8FEU24xYX+GpvN1dZ9FjAuPjzNqAPEDzBQ4LB6JevUPL/hHN
ySy97NgZrauxTMC+SNrxl+Vab4JA9BgPCMXISmdQzzkZUFE5GV3Dq0O4OCiI
NfH1l4n9va0EcqKEwb25

TEXT;
        // }}}

        $directoryName = __DIR__ . '/' . self::HOMEDIR;
        if (!file_exists($directoryName)) {
            mkdir($directoryName);
        }

        $pubring = fopen($this->getKeyringFilename('pubring.gpg'), 'wb');
        fwrite($pubring, base64_decode(str_replace("\n", '', $pubringData)));
        fclose($pubring);

        $secring = fopen($this->getKeyringFilename('secring.gpg'), 'wb');
        fwrite($secring, base64_decode(str_replace("\n", '', $secringData)));
        fclose($secring);

        $trustdb = fopen($this->getKeyringFilename('trustdb.gpg'), 'wb');
        fwrite($trustdb, base64_decode(str_replace("\n", '', $trustdbData)));
        fclose($trustdb);

        $randomSeed = fopen($this->getKeyringFilename('random_seed'), 'wb');
        fwrite($randomSeed, base64_decode(
            str_replace("\n", '', $randomSeedData)));

        fclose($randomSeed);
    }

    // }}}
    // {{{ _setUpTempdir()

    private function _setUpTempdir()
    {
        $directoryName = __DIR__ . '/' . self::TEMPDIR;
        if (!file_exists($directoryName)) {
            mkdir($directoryName);
        }
    }

    // }}}
    // {{{ tearDown()

    public function tearDown()
    {
        unset($this->gpg);

        $this->_tearDownKeyring();
        $this->_tearDownTempdir();
    }

    // }}}
    // {{{ _tearDownKeyring()

    private function _tearDownKeyring()
    {
        $dirnames = array(
            $this->getKeyringFilename('private-keys-v1.d'),
            $this->getKeyringFilename('openpgp-revocs.d')
        );

        foreach ($dirnames as $dirname) {
            if (file_exists($dirname)) {
                $iterator = new DirectoryIterator($dirname);
                foreach ($iterator as $file) {
                    if (!$file->isDot()) {
                        $filename = $dirname . '/' . $file->getFilename();
                        if (file_exists($filename)) {
                            unlink($filename);
                        }
                    }
                }
                rmdir($dirname);
            }
        }

        $homedir  = __DIR__ . '/' . self::HOMEDIR;
        $iterator = new DirectoryIterator($homedir);

        foreach ($iterator as $file) {
            if (!$file->isDot()) {
                $filename = $homedir . '/' . $file->getFilename();
                if (file_exists($filename)) {
                    unlink($filename);
                }
            }
        }

        rmdir($homedir);
    }

    // }}}
    // {{{ _tearDownTempdir()

    private function _tearDownTempdir()
    {
        $directoryName = __DIR__ . '/' . self::TEMPDIR;

        // remove temporary files and temporary directory
        $iterator = new DirectoryIterator($directoryName);
        foreach ($iterator as $file) {
            if (!$file->isDot()) {
                $filename = $this->getTempFilename($file->getFilename());
                if (file_exists($filename)) {
                    if (is_dir($filename)) {
                        rmdir($filename);
                    } else {
                        unlink($filename);
                    }
                }
            }
        }

        rmdir($directoryName);
    }

    // }}}
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
    // {{{ getKeyringFilename()

    protected function getKeyringFilename($filename)
    {
        return __DIR__ . '/'. self::HOMEDIR . '/' . $filename;
    }

    // }}}
    // {{{ getDataFilename()

    protected function getDataFilename($filename)
    {
        return __DIR__ . '/'. self::DATADIR . '/' . $filename;
    }

    // }}}
    // {{{ getTempFilename()

    protected function getTempFilename($filename)
    {
        return __DIR__ . '/' . self::TEMPDIR . '/' . $filename;
    }

    // }}}
    // {{{ assertDecryptAndVerifyResultsEquals()

    protected function assertDecryptAndVerifyResultsEquals(
        array $expected,
        array $actual
    ) {
        $this->assertEquals(
            count($expected),
            count($actual),
            'Result counts are different.'
        );

        $this->assertArrayHasKey(
            'data',
            $expected,
            'Expected result does not include data.'
        );

        $this->assertArrayHasKey(
            'data',
            $actual,
            'Actual result does not include data.'
        );

        $this->assertArrayHasKey(
            'signatures',
            $expected,
            'Expected result does not include signatures.'
        );

        $this->assertArrayHasKey(
            'signatures',
            $actual,
            'Actual result does not include signatures.'
        );

        $this->assertEquals(
            $expected['data'],
            $actual['data'],
            'Decrypted data does not match.'
        );

        $this->assertSignaturesEquals(
            $expected['signatures'],
            $actual['signatures']
        );
    }

    // }}}
    // {{{ assertSignaturesEquals()

    protected function assertSignaturesEquals(
        array $expected,
        array $actual
    ) {
        $this->assertEquals(
            count($expected),
            count($actual),
            'Signature counts are different.'
        );

        for ($i = 0; $i < count($expected); $i++) {
            $this->assertSignatureEquals($expected[$i], $actual[$i]);
        }
    }

    // }}}
    // {{{ assertSignatureEquals()

    protected function assertSignatureEquals(
        Crypt_GPG_Signature $expected,
        Crypt_GPG_Signature $actual
    ) {
        $expectedUserId = $expected->getUserId();
        $actualUserId   = $actual->getUserId();

        $this->assertEquals($expectedUserId, $actualUserId,
            'Signature user ids do not match.'
        );

        $expectedId = $expected->getId();
        $actualId = $actual->getId();

        $this->assertEquals(
            strlen($expectedId),
            strlen($actualId),
            'Signature IDs are of different length.'
        );

        $this->assertEquals(
            $expected->getKeyFingerprint(),
            $actual->getKeyFingerprint(),
            'Signature key fingerprints do not match.'
        );

        $this->assertEquals(
            $expected->getKeyId(),
            $actual->getKeyId(),
            'Signature key IDs do not match.'
        );

        $this->assertEquals(
            $expected->getCreationDate(),
            $actual->getCreationDate(),
            'Signature creation dates do not match.'
        );

        $this->assertEquals(
            $expected->getExpirationDate(),
            $actual->getExpirationDate(),
            'Signature expiration dates do not match.'
        );

        $this->assertEquals(
            $expected->isValid(),
            $actual->isValid(),
            'Signature validity does match.'
        );
    }

    // }}}
}

?>
