<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * This is the package.xml generator for Crypt_GPG
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
 * @author    Nathan Fredrikson <nathan@silverorange.com>
 * @copyright 2005-2013 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

require_once 'PEAR/PackageFileManager2.php';
PEAR::setErrorHandling(PEAR_ERROR_DIE);

$apiVersion     = '1.6.8';
$apiState       = 'stable';

$releaseVersion = '1.6.10';
$releaseState   = 'stable';
$releaseNotes   = "Use short array syntax [alec].\n" .
    "Filter non-scalar ENV values to prevent PHP 8.2 proc_open() warnings [alec].\n" .
    "Tests: Handle OpenPGP-compliant CSF message verfication [dkg].\n" .
    "CI: Add PHP 8.4 [alec]";

$description = "This package provides an object oriented interface to GNU Privacy " .
    "Guard (GnuPG). It requires the GnuPG executable to be on the system.\n\n" .
    "Though GnuPG can support symmetric-key cryptography, this package is " .
    "intended only to facilitate public-key cryptography.\n\n" .
    "This package requires PHP version 5.4.8 or greater.";

$package = new PEAR_PackageFileManager2();

$package->setOptions(
    [
        'filelistgenerator' => 'file',
        'simpleoutput'      => true,
        'baseinstalldir'    => '/',
        'packagedirectory'  => './',
        'dir_roles' => [
            'Crypt'      => 'php',
            'Crypt/GPG'  => 'php',
            'tests'      => 'test',
            'data'       => 'data'
        ],
        'exceptions' => [
            'LICENSE'                    => 'doc',
            'README.md'                  => 'doc',
            'scripts/crypt-gpg-pinentry' => 'script'
        ],
        'ignore' => [
            'tests/config.php',
            'tests/debug.log',
            'tests/.phpunit.result.cache',
            'tools/',
            'package.php',
            'phpstan',
            'phpstan.neon',
            'composer.json',
            'composer.lock',
            '*.tgz',
            'vendor/'
        ],
        'installexceptions' => [
            'scripts/crypt-gpg-pinentry' => '/'
        ]
    ]
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

$package->addMaintainer(
    'lead',
    'alec',
    'Aleksander Machniak',
    'alec@alec.pl'
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

$package->setPhpDep('5.4.8');
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

if (isset($_GET['make'])
    || (isset($_SERVER['argv']) && @$_SERVER['argv'][1] == 'make')
) {
    $package->writePackageFile();
} else {
    $package->debugPackageFile();
}
