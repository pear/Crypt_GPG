<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Decryption tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
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
 * Tests decryption abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class DecryptTestCase extends TestCase
{
    // {{{ testDecrypt()

    /**
     * @group decrypt
     */
    public function testDecrypt()
    {
        $passphrase = 'test';
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with public-and-private@example.com
        // {{{ encrypted data

        $encryptedData = <<<TEXT
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

        $this->gpg->addDecryptKey('public-and-private@example.com',
            $passphrase);

        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptNoPassphrase()

    /**
     * @group decrypt
     */
    public function testDecryptNoPassphrase()
    {
        $expectedDecryptedData = 'Hello, Alice! Goodbye, Bob!';

        // encrypted with no-passphrase@example.com
        // {{{ encrypted data

        $encryptedData = <<<TEXT
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

        $decryptedData = $this->gpg->decrypt($encryptedData);
        $this->assertEquals($expectedDecryptedData, $decryptedData);
    }

    // }}}
    // {{{ testDecryptKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group decrypt
     */
    public function testDecryptKeyNotFoundException()
    {
        $passphrase = 'test';

        // was encrypted with test@example.com
        // {{{ encrypted data

        $encryptedData = <<<TEXT
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

        $decryptedData = $this->gpg->decrypt($encryptedData, $passphrase);
    }

    // }}}
    // {{{ testDecryptNoDataException()

    /**
     * @expectedException Crypt_GPG_NoDataException
     *
     * @group decrypt
     */
    public function testDecryptNoDataException()
    {
        $passphrase = 'test';
        $encryptedData = 'Invalid OpenPGP data.';
        $decryptedData = $this->gpg->decrypt($encryptedData, $passphrase);
    }

    // }}}
    // {{{ testDecryptBadPassphraseException_missing()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group decrypt
     */
    public function testDecryptBadPassphraseException_missing()
    {
        // encrypted with public-and-private@example.com
        // {{{ encrypted data

        $encryptedData = <<<TEXT
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

        $decryptedData = $this->gpg->decrypt($encryptedData);
    }

    // }}}
    // {{{ testDecryptBadPassphraseException_bad()

    /**
     * @expectedException Crypt_GPG_BadPassphraseException
     *
     * @group decrypt
     */
    public function testDecryptBadPassphraseException_bad()
    {
        $passphrase = 'incorrect';

        // encrypted with public-and-private@example.com
        // {{{ encrypted data

        $encryptedData = <<<TEXT
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

        $decryptedData = $this->gpg->decrypt($encryptedData, $passphrase);
    }

    // }}}
}

?>
