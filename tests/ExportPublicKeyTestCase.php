<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Key export tests for the Crypt_GPG package.
 *
 * These tests require the PHPUnit 3.2 package to be installed. PHPUnit is
 * installable using PEAR. See the
 * {@link http://www.phpunit.de/pocket_guide/3.2/en/installation.html manual}
 * for detailed installation instructions.
 *
 * To run these tests, use:
 * <code>
 * $ phpunit ExportPublicKeyTestCase
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
 * Tests key export abilities of Crypt_GPG.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class ExportPublicKeyTestCase extends TestCase
{
    // {{{ testExportPublicKey()

    /**
     * @group export
     */
    public function testExportPublicKey()
    {
        $keyId = 'public-only@example.com';

        // {{{ expected key data
        // OpenPGP header is not included since it varies from system-to-system.
        $expectedKeyData = <<<TEXT
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

        $keyData = $this->gpg->exportPublicKey($keyId);

        // Check for containment rather than equality since the OpenPGP header
        // varies from system to system.
        $this->assertContains($expectedKeyData, $keyData);
    }

    // }}}
    // {{{ testExportPublicKeyNotFoundException()

    /**
     * @expectedException Crypt_GPG_KeyNotFoundException
     *
     * @group export
     */
    public function testExportPublicKeyNotFoundException()
    {
        $keyId = 'non-existent-key@example.com';
        $keyData = $this->gpg->exportPublicKey($keyId);
    }

    // }}}
}

?>
