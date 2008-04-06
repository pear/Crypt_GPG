<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Crypt_GPG is a package to use GPG from PHP
 *
 * This package provides an object oriented interface to GNU Privacy
 * Guard (GPG). It requires the GPG executable to be on the system.
 *
 * Though GPG can support symmetric-key cryptography, this package is intended
 * only to facilitate public-key cryptography.
 *
 * This file contains the main GPG class. The class in this file lets you
 * encrypt, decrypt, sign and verify data; import and delete keys; and perform
 * other useful GPG tasks.
 *
 * Example usage:
 * <code>
 * <?php
 * // encrypt some data
 * $gpg = Crypt_GPG::factory('php');
 * $encrypted_data = $gpg->encrypt($my_secret_key_id, $data);
 * ?>
 * </code>
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
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2007 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 * @link      http://www.gnupg.org/
 */

/**
 * PEAR exception for factory() method.
 */
require_once 'PEAR/Exception.php';

// {{{ class Crypt_GPG

/**
 * A class to use GPG from PHP
 *
 * This class provides an object oriented interface to GNU Privacy Guard (GPG).
 *
 * Though GPG can support symmetric-key cryptography, this class is intended
 * only to facilitate public-key cryptography.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2007 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @link      http://www.gnupg.org/
 */
abstract class Crypt_GPG
{
    // {{{ class error constants

    /**
     * Error code returned when an unknown or unhandled error occurs.
     */
    const ERROR_UNKNOWN            = 0;

    /**
     * Error code returned when a bad passphrase is used.
     */
    const ERROR_BAD_PASSPHRASE     = 1;

    /**
     * Error code returned when a required passphrase is missing.
     */
    const ERROR_MISSING_PASSPHRASE = 2;

    /**
     * Error code returned when a key that is already in the keyring is
     * imported.
     */
    const ERROR_DUPLICATE_KEY      = 3;

    /**
     * Error code returned the required data is missing for an operation.
     *
     * This could be missing key data, missing encrypted data or missing
     * signature data.
     */
    const ERROR_NO_DATA            = 4;

    /**
     * Error code returned when an unsigned key is used.
     */
    const ERROR_UNSIGNED_KEY       = 5;

    /**
     * Error code returned when a key that is not self-signed is used.
     */
    const ERROR_NOT_SELF_SIGNED    = 6;

    /**
     * Error code returned when a public or private key that is not in the
     * keyring is used.
     */
    const ERROR_KEY_NOT_FOUND      = 7;

    /**
     * Error code returned when an attempt to delete public key having a
     * private key is made.
     */
    const ERROR_DELETE_PRIVATE_KEY = 8;

    // }}}
    // {{{ class constants for data signing modes

    /**
     * Signing mode for normal signing of data. The signed message will not
     * be readable without special software.
     *
     * This is the default signing mode.
     *
     * @see Crypt_GPG::sign()
     */
    const SIGN_MODE_NORMAL   = 1;

    /**
     * Signing mode for clearsigning data. Clearsigned signatures are ASCII
     * armored data and are readable without special software. If the signed
     * message is unencrypted, the message will still be readable. The message
     * text will be in the original encoding.
     *
     * @see Crypt_GPG::sign()
     */
    const SIGN_MODE_CLEAR    = 2;

    /**
     * Signing mode for creating a detached signature. When using detached
     * signatures, only the signature data is returned. The original message
     * text may be distributed separately from the signature data. This is
     * useful for miltipart/signed email messages as per
     * {@link http://www.ietf.org/rfc/rfc3156.txt RFC 3156}.
     *
     * @see Crypt_GPG::sign()
     */
    const SIGN_MODE_DETACHED = 3;

    // }}}
    // {{{ class constants for fingerprint formats

    /**
     * No formatting is performed.
     *
     * Example: C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4
     *
     * @see Crypt_GPG::getFingerprint()
     */
    const FORMAT_NONE      = 1;

    /**
     * Fingerprint is formatted in the format used by the GnuPG gpg command's
     * default output.
     *
     * Example: C3BC 615A D9C7 66E5 A85C  1F27 16D2 7458 B1BB A1C4
     *
     * @see Crypt_GPG::getFingerprint()
     */
    const FORMAT_CANONICAL = 2;
    /**
     * Fingerprint is formatted in the format used when displaying X.509
     * certificates
     *
     * Example: C3:BC:61:5A:D9:C7:66:E5:A8:5C:1F:27:16:D2:74:58:B1:BB:A1:C4
     *
     */
    const FORMAT_X509      = 3;

    // }}}
    // {{{ factory()

    /**
     * Static factory method to create a new GPG object using the specified
     * backend driver
     *
     * This allows developers to write code using a standard interface and
     * optionally switch to a PECL-based implementation with minimal fuss at a
     * later date.
     *
     * @param string $driver  optional. The name of the driver to use. Valid
     *                        driver names are 'php' for a native PHP driver
     *                        and 'gnupg' for a PECL-powered driver. If not
     *                        specified, the native PHP driver is used.
     * @param array  $options optional. An array of options passed to the
     *                        driver's constructor. All options must be
     *                        optional and are represented as key-value pairs.
     *                        See documentation of a specific driver for
     *                        details on what options are available.
     *
     * @return Crypt_GPG a GPG object powered by the speficied driver.
     */
    public static function factory($driver = 'php', array $options = array())
    {
        $drivers = array(
            'php'   => 'Php',
            'gnupg' => 'GnuPG'
        );

        if (!array_key_exists($driver, $drivers)) {
            throw new PEAR_Exception(sprintf("Crypt_GPG driver '%s' not " .
                "supported.", $driver));
        }

        include_once 'Crypt/GPG/Driver/' . $drivers[$driver] . '.php';

        $class_name = 'Crypt_GPG_Driver_' . $drivers[$driver];
        $object = new $class_name($options);
        return $object;
    }

    // }}}
    // {{{ __construct()

    /**
     * Creates a new Crypt_GPG object
     *
     * The {@link Crypt_GPG::factory()} method must be used to instantiate a
     * Crypt_GPG object.
     *
     * @param array $options optional. An array of options used to create the
     *                       GPG object. All options must be optional and are
     *                       represented as key-value pairs.
     */
    abstract protected function __construct(array $options = null);

    // }}}
    // {{{ importKey()

    /**
     * Imports a public or private key into the keyring
     *
     * Keys may be removed from the keyring using
     * {@link Crypt_GPG::deletePublicKey()} or
     * {@link Crypt_GPG::deletePrivateKey()}.
     *
     * @param string $data the key data to be imported.
     *
     * @return array an associative array containing the following elements:
     *               - fingerprint: the key fingerprint of the imported key,
     *               - public_imported: the number of public keys imported,
     *               - public_unchanged: the number of unchanged public keys,
     *               - private_imported: the number of private keys imported,
     *               - private_unchanged: the number of unchanged private keys.
     *
     * @throws Crypt_GPG_NoDataException if the key data is missing or if the
     *         data is is not valid key data.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     */
    abstract public function importKey($data);

    // }}}
    // {{{ exportPublicKey()

    /**
     * Exports a public key from the keyring
     *
     * The exported key remains on the keyring. To delete the public key, use
     * {@link Crypt_GPG::deletePublicKey()}.
     *
     * If more than one key fingerprint is avaliable for the specified
     * <i>$key_id</i> (for example, if you use a non-unique uid) only the first
     * public key is exported.
     *
     * @param string  $key_id either the full uid of the public key, the email
     *                        part of the uid of the public key or the key id of
     *                        the public key. For example,
     *                        "Test User (example) <test@example.com>",
     *                        "test@example.com" or a hexidecimal string.
     * @param boolean $armor  optional. If true, ASCII armored data is returned;
     *                        otherwise, binary data is returned. Defaults to
     *                        true.
     *
     * @return string the public key data.
     *
     * @throws Crypt_GPG_KeyNotFoundException if a public key with the given
     *         <i>$key_id</i> is not found.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     */
    abstract public function exportPublicKey($key_id, $armor = true);

    // }}}
    // {{{ deletePublicKey()

    /**
     * Deletes a public key from the keyring
     *
     * If more than one key fingerprint is avaliable for the specified
     * <i>$key_id</i> (for example, if you use a non-unique uid) only the first
     * public key is deleted.
     *
     * The private key must be deleted first or an exception will be thrown.
     * See {@link Crypt_GPG::deletePrivateKey()}.
     *
     * @param string $key_id either the full uid of the public key, the email
     *                       part of the uid of the public key or the key id of
     *                       the public key. For example,
     *                       "Test User (example) <test@example.com>",
     *                       "test@example.com" or a hexidecimal string.
     *
     * @return void
     *
     * @throws Crypt_GPG_KeyNotFoundException if a public key with the given
     *         <i>$key_id</i> is not found.
     *
     * @throws Crypt_GPG_DeletePrivateKeyException if the specified public key
     *         has an associated private key on the keyring. The private key
     *         must be deleted first.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     */
    abstract public function deletePublicKey($key_id);

    // }}}
    // {{{ deletePrivateKey()

    /**
     * Deletes a private key from the keyring
     *
     * If more than one key fingerprint is avaliable for the specified
     * <i>$key_id</i> (for example, if you use a non-unique uid) only the first
     * private key is deleted.
     *
     * @param string $key_id either the full uid of the private key, the email
     *                       part of the uid of the private key or the key id of
     *                       the private key. For example,
     *                       "Test User (example) <test@example.com>",
     *                       "test@example.com" or a hexidecimal string.
     *
     * @return void
     *
     * @throws Crypt_GPG_KeyNotFoundException if a private key with the given
     *         <i>$key_id</i> is not found.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     */
    abstract public function deletePrivateKey($key_id);

    // }}}
    // {{{ getKeys()

    /**
     * Gets the available keys in the keyring
     *
     * @param string $key_id optional. Only keys with that match the specified
     *                       pattern are returned. The pattern may be part of
     *                       a user id, a key id or a key fingerprint. If not
     *                       specified, all keys are returned.
     *
     * @return array an array of {@link Crypt_GPG_Key} objects.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     *
     * @see Crypt_GPG_Key
     */
    abstract public function getKeys($key_id = '');

    // }}}
    // {{{ getFingerprint()

    /**
     * Gets a key fingerprint from the keyring
     *
     * If more than one key fingerprint is avaliable (for example, if you use
     * a non-unique user id) only the first key fingerprint is returned.
     *
     * @param string  $key_id either the full user id of the key, the email
     *                        part of the user id of the key, or the key id of
     *                        the key. For example,
     *                        "Test User (example) <test@example.com>",
     *                        "test@example.com" or a hexidecimal string.
     * @param integer $format optional. How the fingerprint should be formatted.
     *                        Use {@link Crypt_GPG::FORMAT_X509} for X.509
     *                        certificate format,
     *                        {@link Crypt_GPG::FORMAT_CANONICAL} for the format
     *                        used by GnuPG output and
     *                        {@link Crypt_GPG::FORMAT_NONE} for no formatting.
     *                        Defaults to Crypt_GPG::FORMAT_NONE.
     *
     * @return string the fingerprint of the key, or null if no fingerprint
     *                is found for the given <i>$key_id</i>.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     */
    abstract public function getFingerprint($key_id,
        $format = self::FORMAT_NONE);

    // }}}
    // {{{ encrypt()

    /**
     * Encrypts string data
     *
     * Data is ASCII armored by default but may optionally be returned as
     * binary.
     *
     * If this method throws a Crypt_GPG_MissingSelfSignatureException, the
     * public key needs to be signed. Keys may be manually signed using the
     * shell command:
     *
     * <code>gpg --sign-key <key-id> <named-user></code>
     *
     * @param string  $key_id the full uid of the public key to use for
     *                        encryption. For example,
     *                        "Test User (example) <test@example.com>".
     * @param string  $data   the data to be encrypted.
     * @param boolean $armor  optional. If true, ASCII armored data is returned;
     *                        otherwise, binary data is returned. Defaults to
     *                        true.
     *
     * @return string the encrypted data.
     *
     * @throws Crypt_GPG_KeyNotFoundException if the a key with the given
     *         <i>$key_id</i> is not found.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     *
     * @sensitive $data
     */
    abstract public function encrypt($key_id, $data, $armor = true);

    // }}}
    // {{{ decrypt()

    /**
     * Decrypts string data using the given passphrase
     *
     * This method assumes the required private key is available in the keyring
     * and throws an exception if the private key is not available. To add a
     * private key to the keyring, use the {@link Crypt_GPG::importKey()}
     * method.
     *
     * @param string $encrypted_data the data to be decrypted.
     * @param string $passphrase     optional. The passphrase of the private
     *                               key used to encrypt the data. Only
     *                               required if the private key requires a
     *                               passphrase.
     *
     * @return string the decrypted data.
     *
     * @throws Crypt_GPG_KeyNotFoundException if the private key needed to
     *         decrypt the data is not in the user's keyring.
     *
     * @throws Crypt_GPG_NoDataException if specified data does not contain
     *         GPG encrypted data.
     *
     * @throws Crypt_GPG_BadPassphraseException if specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     *
     * @sensitive $passphrase
     */
    abstract public function decrypt($encrypted_data, $passphrase = null);

    // }}}
    // {{{ sign()

    /**
     * Signs data using the given key and passphrase
     *
     * Data may be signed using any one of the three available signing modes:
     * - {@link Crypt_GPG::SIGN_MODE_NORMAL}
     * - {@link Crypt_GPG::SIGN_MODE_CLEAR}
     * - {@link Crypt_GPG::SIGN_MODE_DETACHED}
     *
     * @param string  $key_id     either the full uid of the private key, the
     *                            email part of the uid of the private key or
     *                            the key id of the private key. For example,
     *                            "Test User (example) <test@example.com>",
     *                            "test@example.com" or a hexidecimal string.
     * @param string  $data       the data to be signed.
     * @param string  $passphrase optional. The passphrase of the private key
     *                            used to sign the data. Only required if the
     *                            private key requires a passphrase. Specify
     *                            null for no passphrase.
     * @param boolean $mode       otional. The data signing mode to use. Should
     *                            be one of {@link Crypt_GPG::SIGN_MODE_NORMAL},
     *                            {@link Crypt_GPG::SIGN_MODE_CLEAR} or
     *                            {@link Crypt_GPG::SIGN_MODE_DETACHED}. If not
     *                            specified, defaults to
     *                            Crypt_GPG::SIGN_MODE_NORMAL.
     * @param boolean $armor      optional. If true, ASCII armored data is
     *                            returned; otherwise, binary data is returned.
     *                            Defaults to true. This has no effect if the
     *                            mode Crypt_GPG::SIGN_MODE_CLEAR is used.
     *
     * @return string the signed data, or the signature data if a detached
     *                signature is requested.
     *
     * @throws Crypt_GPG_KeyNotFoundException if the private key is not in the
     *         user's keyring. Signing data requires the private key.
     *
     * @throws Crypt_GPG_BadPassphraseException if specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     *
     * @sensitive $passphrase
     */
    abstract public function sign($key_id, $data, $passphrase = null,
        $mode = self::SIGN_MODE_NORMAL, $armor = true);

    // }}}
    // {{{ verify()

    /**
     * Verifies signed data
     *
     * The {@link Crypt_GPG::decrypt()} method may be used to get the original
     * message if the signed data is not clearsigned and does not have a
     * detached signature.
     *
     * @param string $signed_data the signed data to be verified.
     * @param string $signature   optional. If verifying data signed using a
     *                            detached signature, this must be the detached
     *                            signature data. The data that was signed is
     *                            specified in <i>$signed_data</i>.
     *
     * @return Crypt_GPG_Signature the signature details of the signed data. If
     *                             the signature is valid, the <i>$valid</i>
     *                             property of the returned object will be true.
     *
     * @throws Crypt_GPG_NoDataException if the provided data is not signed
     *         data.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         Use {@link Crypt_GPG::$debug} and file a bug report if these
     *         exceptions occur.
     *
     * @see Crypt_GPG_Signature
     */
    abstract public function verify($signed_data, $signature = '');

    // }}}
}

// }}}

?>
