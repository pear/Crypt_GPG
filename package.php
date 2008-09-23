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
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

require_once 'PEAR/PackageFileManager2.php';
PEAR::setErrorHandling(PEAR_ERROR_DIE);

$release_version = '0.7.1';
$release_state   = 'beta';
$release_notes   =
    "Small cleanups in generated API documentation. See 0.7.0 release " .
    "notes:\n\n" .
    "Brought to you by strace, xdebug, time and phpunit.\n\n" .
    "API is beta -- there are significant API changes in this release. See " .
    "the API or end-user documentation for details. Other changes in this " .
    "release include:\n" .
    " * support operations on large strings properly. Bug #13806.\n" .
    " * support operations on files (or anything fopen-able). Bug #13586.\n" .
    " * encryption speed improvements (went from 10 seconds to encrypt a " .
    "   1.9 MiB file to 0.1 - 0.2 seconds). There is new file-specific API. " .
    "   see the API docs for details.\n" .
    " * remove GnuPG driver and driver architecture [BC BREAK]. The pecl " .
    "   extension powering the GnuPG driver is missing features and doesn't " .
    "   support any extra features that make it desirable to use. Crypt_GPG " .
    "   still has nicer error handling, a greater feature set, better " .
    "   documentation and more comprehensive tests.\n" .
    " * split GPG I/O engine into a separate class\n" .
    " * support multiple encryption, decryption and signing recipients " .
    "   [BC BREAK]. Bug #13808. This moves the API towards something more " .
    "   like the PECL gnupg extension where you add and clear keys for a " .
    "   particular operation. This also changes the returned value of " .
    "   verify() from a signature object to an array of signature objects.\n" .
    " * use PHP_EOL for detecting line endings.\n" .
    " * throw an exception if keychain can not be read or written. " .
    "   Bug #14645.\n" .
    " * split unit tests into separate files.\n" .
    " * updated unit tests for new API and features.\n" .
    " * throw a KeyNotFound exception if trying to verify a signature when " .
    "   the public key is not in the keyring.\n" .
    " * drop Windows support. PHP bugs and known limitations make it next " .
    "   to impossible to develop for Windows correctly.\n";


$description =
    "This package provides an object oriented interface to GNU Privacy ".
    "Guard (GPG). It requires the GPG executable to be on the system.\n\n".
    "Though GPG can support symmetric-key cryptography, this package is ".
    "intended only to facilitate public-key cryptography.\n\n".
    "This package requires PHP version 5.2.1 or greater.";

$package = new PEAR_PackageFileManager2();

$package->setOptions(array(
    'filelistgenerator' => 'cvs',
    'simpleoutput'      => true,
    'baseinstalldir'    => '/Crypt',
    'packagedirectory'  => './',
    'dir_roles'         => array(
        'GPG'        => 'php',
        'tests'      => 'test'
    ),
    'exceptions'        => array(
        'LICENSE' => 'doc',
        'GPG.php' => 'php'
    ),
    'ignore'            => array(
        'tools/'
    )
));

$package->setPackage('Crypt_GPG');
$package->setSummary('GNU Privacy Guard (GPG)');
$package->setDescription($description);
$package->setChannel('pear.php.net');
$package->setPackageType('php');
$package->setLicense('LGPL', 'http://www.gnu.org/copyleft/lesser.html');

$package->setNotes($release_notes);
$package->setReleaseVersion($release_version);
$package->setReleaseStability($release_state);
$package->setAPIVersion('0.7.0');
$package->setAPIStability('beta');

$package->addIgnore('package.php');
$package->addIgnore('*.tgz');

$package->addMaintainer('lead', 'gauthierm', 'Mike Gauthier',
    'mike@silverorange.com');

$package->addMaintainer('lead', 'nrf', 'Nathan Fredrickson',
    'nathan@silverorange.com');

$package->setPhpDep('5.2.1');
$package->addOsDep('windows', true);
$package->setPearinstallerDep('1.4.0');
$package->generateContents();

if (isset($_GET['make']) || (isset($_SERVER['argv']) && @$_SERVER['argv'][1] == 'make')) {
    $package->writePackageFile();
} else {
    $package->debugPackageFile();
}

?>
