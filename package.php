<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

require_once 'PEAR/PackageFileManager2.php';

$version = '0.3.9';
$notes = <<<EOT
see ChangeLog
EOT;

$description =<<<EOT
This class provides an object oriented interface to GNU Privacy Guard (GPG).
EOT;

$package = new PEAR_PackageFileManager2();
PEAR::setErrorHandling(PEAR_ERROR_DIE);

$result = $package->setOptions(array(
    'filelistgenerator' => 'svn',
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
$package->setChannel('pear.silverorange.com');
$package->setPackageType('php');
$package->setLicense('LGPL', 'http://www.gnu.org/copyleft/lesser.html');

$package->setReleaseVersion($version);
$package->setReleaseStability('alpha');
$package->setAPIVersion('0.3.0');
$package->setAPIStability('alpha');
$package->setNotes($notes);

$package->addIgnore('package.php');
$package->addIgnore('package-2.0.xml');

$package->addMaintainer('lead', 'gauthierm', 'Mike Gauthier',
    'mike@silverorange.com');

$package->addMaintainer('lead', 'nrf', 'Nathan Fredrickson',
    'nathan@silverorange.com');

$package->setPhpDep('5.0.5');
$package->setPearinstallerDep('1.4.0');
$package->generateContents();

if (isset($_GET['make']) || (isset($_SERVER['argv']) && @$_SERVER['argv'][1] == 'make')) {
    $package->writePackageFile();
} else {
    $package->debugPackageFile();
}

?>
