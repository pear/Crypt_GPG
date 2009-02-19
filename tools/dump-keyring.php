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

echo "\n?>\n";

?>
