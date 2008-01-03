<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * A test script for the Crypt_GPG class.
 *
 * The following commands create a test key pair required by this test script:
 *
 * As yourself, generate a new key pair for test@example.com:
 * <pre>
 *   gpg --gen-key
 * </pre>
 *
 * This command is interactive.  Accept the default key type and size parameters,
 * but name the key as:
 * <pre>
 *   Real Name: Test User
 *   Email: test@example.com
 *   Passphrase: example
 * </pre>
 * This new key will be automatically added to your keychain and signed.
 *
 * The test script needs access to the private key for decryption. In practice
 * these would come from the user via file uploads and form field data.
 * For testing purposes only, extract the test private key to a file:
 * <pre>
 *   gpg --armor --export-secret-key test@example.com > /tmp/test.secret
 * </pre>
 *
 * Now the test can be run on the commandline:
 * <pre>
 *   php -f test.php
 * </pre>
 *
 * When running through apache, rather than as yourself on the command line,
 * apache will need the test public key in its key chain.  First export the
 * public key of the test user:
 * <pre>
 *   gpg -armor --export test@example.com > /tmp/test.pub
 * </pre>
 *
 * Then import the public key into apache's keychain by running the following
 * as the apache user:
 * <pre>
 *   gpg --import < /tmp/test.pub
 *   gpg --sign-key test@example.com
 * </pre>
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
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * The Crypt_GPG class to test
 */
require 'Crypt/GPG.php';

/**
 * Fancy output function for test results
 *
 * Indents test output by four spaces and echos the result.
 *
 * @param string $text the output text to display.
 */
function output($text)
{
    foreach (explode("\n", $text) as $line) {
        echo str_repeat(' ', 4), $line, "\n";
    }
    echo "\n";
}

/**
 * Displays a test section title
 *
 * @param string $title the title of the test section.
 */
function section($title)
{
    echo $title, "\n";
}

$data = 'Hello, World!';
$key_id = 'test@example.com';

/*
 * In practice these would come from the user via
 * file uploads and form field data.
 */
$private_key_file = '/tmp/test.secret';
$private_key_passphrase = 'example';

// display original, unencrypted data
section('Original data:');
output($data);

// Test the constructor
section('Make a new Crypt_GPG object:');
try {
    $crypt_gpg = Crypt_GPG::factory();
    //$crypt_gpg->debug = true;
    output('Created successfully.');
} catch (Crypt_GPG_Exception $e) {
    output('Error creating Crypt_GPG object: ' . $e->getMessage());
}

// Test encrypting data
section('Encrypted data:');
try {
    $encdata = $crypt_gpg->encrypt($key_id, $data);
    output($encdata);
} catch (Crypt_GPG_Exception $e) {
    $encdata = null;
    output('Error encrypting data: ' . $e->getMessage());
}

// Test importing a key into keychain
section('Import private key:');
try {
    $crypt_gpg->importKey(file_get_contents($private_key_file));
    output('Imported private key.');
} catch (Crypt_GPG_Exception $e) {
    output('Error inporting private key: ' . $e->getMessage());
}

// Test signing data
section('Signed data:');
try {
    $signed_data = $crypt_gpg->sign($key_id, $data, $private_key_passphrase);
    output($signed_data);
} catch (Crypt_GPG_Exception $e) {
    $signed_data = null;
    output('Error signing data: ' . $e->getMessage());
}

// Test verify signed data
section('Verify signed data:');
if ($signed_data === null) {
    output('Signed data not found. Skipping verify() signed data test.');
} else {
    try {
        $signature = $crypt_gpg->verify($signed_data);
        output(print_r($signature, true));
    } catch (Crypt_GPG_Exception $e) {
        output('Error verifying signed data: ' . $e->getMessage());
    }
}

// Test clearsigning data
section('Clearsigned data:');
try {
    $signed_data = $crypt_gpg->sign($key_id, $data, $private_key_passphrase,
        Crypt_GPG::SIGN_MODE_CLEAR);

    output($signed_data);
} catch (Crypt_GPG_Exception $e) {
    $signed_data = null;
    output('Error signing data: ' . $e->getMessage());
}

// Test verify clearsigned data
section('Verify clearsigned data:');
if ($signed_data === null) {
    output('Signed data not found. Skipping verify() clearsigned data test.');
} else {
    try {
        $signature = $crypt_gpg->verify($signed_data);
        output(print_r($signature, true));
    } catch (Crypt_GPG_Exception $e) {
        output('Error verifying clearsigned data: ' . $e->getMessage());
    }
}

// Test making a detached signature
section('Detached signature data:');
try {
    $signature_data = $crypt_gpg->sign($key_id, $data, $private_key_passphrase,
        Crypt_GPG::SIGN_MODE_DETACHED);

    output($signed_data);
} catch (Crypt_GPG_Exception $e) {
    $signature_data = null;
    output('Error signing data: ' . $e->getMessage());
}

// Test verify detached signature
section('Verify detached signature:');
if ($signature_data === null) {
    output('Signature data not found. ' .
        'Skipping verify() detached signature test.');
} else {
    try {
        $signature = $crypt_gpg->verify($data, $signature_data);
        output(print_r($signature, true));
    } catch (Crypt_GPG_Exception $e) {
        output('Error verifying detached signature: ' . $e->getMessage());
    }
}

// Test getting public keys
section('Get public keys:');
try {
    $keys = $crypt_gpg->getPublicKeys();
    output(print_r($keys, true));
} catch (Crypt_GPG_Exception $e) {
    $keys = array();
    output('Error getting public keys: ' . $e->getMessage());
}

// Test getting public key fingerprint
section('Get public key fingerprint:');
if (count($keys)) {
    try {
        $key = reset($keys); // get first key
        $fingerprint = $crypt_gpg->getPublicFingerprint($key->id);
        output('Fingerprint for key with an id of "' . $key->id . '" is "' .
            $fingerprint . '".');
    } catch (Crypt_GPG_Exception $e) {
        output('Error getting key fingerprint:' . $e->getMessage());
    }
} else {
    output('No public keys found. Skipping getPublicFingerprint() test.');
}

// Test getting private keys
section('Get private keys:');
try {
    $keys = $crypt_gpg->getPrivateKeys();
    output(print_r($keys, true));
} catch (Crypt_GPG_Exception $e) {
    $keys = array();
    output('Error getting private keys: ' . $e->getMessage());
}

// Test getting key fingerprint
section('Get private key fingerprint:');
if (count($keys)) {
    try {
        $key = reset($keys); // get first key
        $fingerprint = $crypt_gpg->getPrivateFingerprint($key->id);
        output('Fingerprint for key with an id of "' . $key->id . '" is "' .
            $fingerprint . '".');
    } catch (Crypt_GPG_Exception $e) {
        output('Error getting key fingerprint:' . $e->getMessage());
    }
} else {
    output('No private keys found. Skipping getPrivateFingerprint() test.');
}

// Test decrypting data
section('Decrypted data:');
try {
    if ($encdata === null) {
        output('No encrypted data. Skipping decrypt() test.');
    } else {
        $decdata = $crypt_gpg->decrypt($encdata, $private_key_passphrase);
        output($decdata);
    }
} catch (Crypt_GPG_Exception $e) {
    output('Error decrypting data: ' . $e->getMessage());
}

// Test deleting a private key from keychain
section('Delete private key:');
try {
    $crypt_gpg->deletePrivateKey($key_id);
    output('Private key deleted from keychain.');
} catch (Crypt_GPG_Exception $e) {
    output('Error deleting private key: ' . $e->getMessage());
}

?>
