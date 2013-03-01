<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * This is the package.xml generator for Crypt_GPG
 *
 * PHP version 5
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
 * @author    Nathan Fredrikson <nathan@silverorange.com>
 * @copyright 2005-2013 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

require_once 'PEAR/PackageFileManager2.php';
PEAR::setErrorHandling(PEAR_ERROR_DIE);

$apiVersion     = '1.4.0';
$apiState       = 'beta';

$releaseVersion = '1.4.0b2';
$releaseState   = 'beta';
$releaseNotes   =
    "This release adds support for GnuPG 2.x, supporting the latest version " .
    "of RHEL and derivatives. Additionally, the following bugs are fixed:\n" .
    "\n" .
    "Fix Bug #17838. Passphrase operations don't work on GnuPG 2.x.\n" .
    "Fix Bug #17628. Version regular expression on MAMP.\n" .
    "Fix Bug #19883. Better exception on unwriteable or unexecutable homedir.\n" .
    "\n" .
    "A workaround for PHP Bug #39598 is also provided in the event that " .
    "GnuPG ends unexpectedly. This prevents infinite loops.\n" .
    "\n" .
    "This release makes the mbstring extension a required dependency as the " .
    "assuan protocol used in GnuPG 2.x uses UTF-8.\n";

$description =
    "This package provides an object oriented interface to GNU Privacy " .
    "Guard (GnuPG). It requires the GnuPG executable to be on the system.\n\n" .
    "Though GnuPG can support symmetric-key cryptography, this package is " .
    "intended only to facilitate public-key cryptography.\n\n" .
    "This package requires PHP version 5.2.1 or greater.";

$package = new PEAR_PackageFileManager2();

$package->setOptions(
    array(
        'filelistgenerator' => 'file',
        'simpleoutput'      => true,
        'baseinstalldir'    => '/',
        'packagedirectory'  => './',
        'dir_roles'         => array(
            'Crypt'         => 'php',
            'Crypt/GPG'     => 'php',
            'tests'         => 'test',
            'data'          => 'data'
        ),
        'exceptions'        => array(
            'LICENSE'       => 'doc',
            'README.md'     => 'doc',
            'scripts/crypt-gpg-pinentry' => 'script'
        ),
        'ignore'            => array(
            'tests/config.php',
            'tools/',
            'package.php',
            '*.tgz'
        ),
        'installexceptions' => array(
            'scripts/crypt-gpg-pinentry' => '/'
        )
    )
);

$package->setPackage('Crypt_GPG');
$package->setSummary('GNU Privacy Guard (GnuPG)');
$package->setDescription($description);
$package->setChannel('pear.php.net');
$package->setPackageType('php');
$package->setLicense('LGPL', 'http://www.gnu.org/copyleft/lesser.html');

$package->setNotes($releaseNotes);
$package->setReleaseVersion($releaseVersion);
$package->setReleaseStability($releaseState);
$package->setAPIVersion($apiVersion);
$package->setAPIStability($apiState);

$package->addMaintainer(
    'lead',
    'gauthierm',
    'Mike Gauthier',
    'mike@silverorange.com'
);

$package->addMaintainer(
    'lead',
    'nrf',
    'Nathan Fredrickson',
    'nathan@silverorange.com'
);

$package->addReplacement(
    'data/pinentry-cli.xml',
    'package-info',
    '@package-version@',
    'version'
);

$package->addReplacement(
    'Crypt/GPG/PinEntry.php',
    'package-info',
    '@package-name@',
    'name'
);

$package->addReplacement(
    'Crypt/GPG/PinEntry.php',
    'pear-config',
    '@data-dir@',
    'data_dir'
);

$package->addReplacement(
    'Crypt/GPG/Engine.php',
    'pear-config',
    '@bin-dir@',
    'bin_dir'
);

$package->addReplacement(
    'scripts/crypt-gpg-pinentry',
    'pear-config',
    '@php-dir@',
    'php_dir'
);

$package->setPhpDep('5.2.1');
$package->addExtensionDep('optional', 'posix');
$package->addExtensionDep('required', 'mbstring');
$package->addOsDep('windows', true);
$package->setPearinstallerDep('1.4.0');
$package->addPackageDepWithChannel(
    'required',
    'Console_CommandLine',
    'pear.php.net',
    '1.1.10'
);

$package->generateContents();

$package->addRelease();
$package->addInstallAs(
    'scripts/crypt-gpg-pinentry',
    'crypt-gpg-pinentry'
);

if (   isset($_GET['make'])
    || (isset($_SERVER['argv']) && @$_SERVER['argv'][1] == 'make')
) {
    $package->writePackageFile();
} else {
    $package->debugPackageFile();
}

?>
