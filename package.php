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

$release_version = '0.5.0';
$release_state   = 'beta';
$release_notes   =
    "API is beta. No API changes in this release. Changes in this release:\n" .
    " * added PECL-powered gnupg driver,\n" .
    " * added unit tests for new driver.\n";

$description =
    "This package provides an object oriented interface to GNU Privacy ".
    "Guard (GPG). It requires the GPG executable to be on the system.\n\n".
    "Though GPG can support symmetric-key cryptography, this package is ".
    "intended only to facilitate public-key cryptography.\n\n".
    "This package requires PHP version 5.1 or greater.";

$package = new PEAR_PackageFileManager2();

$package->setOptions(array(
    'filelistgenerator' => 'cvs',
    'simpleoutput'      => true,
    'baseinstalldir'    => '/Crypt',
    'packagedirectory'  => './',
    'dir_roles'         => array(
        'GPG'        => 'php',
        'GPG/Driver' => 'php',
        'tests'      => 'test'
    ),
    'exceptions'        => array(
        'LICENSE' => 'doc',
        'GPG.php' => 'php'
    ),
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
$package->setAPIVersion('0.5.0');
$package->setAPIStability('beta');

$package->addIgnore('package.php');
$package->addIgnore('package-2.0.xml');
$package->addIgnore('*.tgz');

$package->addMaintainer('lead', 'gauthierm', 'Mike Gauthier',
    'mike@silverorange.com');

$package->addMaintainer('lead', 'nrf', 'Nathan Fredrickson',
    'nathan@silverorange.com');

$package->setPhpDep('5.1.0');
$package->addExtensionDep('optional', 'gnupg');
$package->setPearinstallerDep('1.4.0');
$package->generateContents();

if (isset($_GET['make']) || (isset($_SERVER['argv']) && @$_SERVER['argv'][1] == 'make')) {
    $package->writePackageFile();
} else {
    $package->debugPackageFile();
}

?>
