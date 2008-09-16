<?php

/*
 * Helper script for test keyring generation
 *
 * See build-keyring.sh
 *
 * Copyright (c) 2008 Michael Gauthier
 */

echo "<?php\n\n";

$HOMEDIR = $_SERVER['argv'][1];

$dataFiles = array(
	'pubring'     => 'pubring.gpg',
	'secring'     => 'secring.gpg',
	'trustdb'     => 'trustdb.gpg',
	'random_seed' => 'random_seed'
);

$keyFiles = array(
	'expectedKeyData'   => 'public-only-pub.asc',
	'privateKeyData'    => 'public-only-sec.asc',
	'publicKeyData'     => 'external-public-pub.asc'
);

$signatureFiles = array(
	'normalSignedData'      => 'normal-signed-data.asc',
	'clearsignedData'       => 'clearsigned-data.asc',
	'detachedSignature'     => 'detached-signature.asc',
	'dualNormalSignedData'  => 'dual-normal-signed-data.asc',
	'dualClearsignedData'   => 'dual-clearsigned-data.asc',
	'dualDetachedSignature' => 'dual-detached-signature.asc'
);

$encryptedFiles = array(
	'encryptedData'                  => 'encrypted-data.asc',
	'encryptedDataNoPassphrase'      => 'encrypted-data-no-passphrase.asc',
	'encryptedDataMissingKey'        => 'encrypted-data-missing-key.asc',
	'dualEncryptedData'              => 'dual-encrypted-data.asc',
	'dualEncryptedDataOnePassphrase' => 'dual-encrypted-data-one-passphrase.asc'
);

echo "\n// For TestCase\n";

foreach ($dataFiles as $key => $file) {
	echo "        // {{{ " . $key . " data\n";
	echo "        $" . $key . "Data = <<<TEXT\n";

	$content = file_get_contents($HOMEDIR . '/' . $file);
	$content = base64_encode($content);
	$content = wordwrap($content, 60, "\n", true);

	echo $content;

	echo "\n\nTEXT;\n";
	echo "        // }}}\n";
}

echo "\n// For ImportKeyTestCase and ExportKeyTestCase\n";

foreach ($keyFiles as $key => $file) {
	$comment = strtolower(preg_replace('([A-Z])', ' ${0}', $key));

	echo "        // {{{ " . $comment . "\n";
	echo "        $" . $key . " = <<<TEXT\n";

	$content = file_get_contents($HOMEDIR . '/' . $file);

	echo $content;

	echo "\nTEXT;\n";
	echo "        // }}}\n";
}

echo "\n// For SignTestCase and VerifyTestCase\n";

foreach ($signatureFiles as $key => $file) {
	$comment = strtolower(preg_replace('([A-Z])', ' ${0}', $key));

	echo "        // {{{ " . $comment . "\n";
	echo "        $" . $key . " = <<<TEXT\n";

	$content = file_get_contents($HOMEDIR . '/' . $file);

	echo $content;

	echo "\nTEXT;\n";
	echo "        // }}}\n";
}

echo "\n// For DecryptTestCase\n";

foreach ($encryptedFiles as $key => $file) {
	$comment = strtolower(preg_replace('([A-Z])', ' ${0}', $key));

	echo "        // {{{ " . $comment . "\n";
	echo "        $" . $key . " = <<<TEXT\n";

	$content = file_get_contents($HOMEDIR . '/' . $file);

	echo $content;

	echo "\nTEXT;\n";
	echo "        // }}}\n";
}

echo "\n?>\n";

?>
