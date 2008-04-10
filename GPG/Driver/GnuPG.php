<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Crypt_GPG is a package to use GPG from PHP
 *
 * This file contains an implementation of the GPG object class that uses the
 * PECL gnupg extension. The gnupg extension is used to handle the GPG process.
 *
 * Unlike the native PHP Crypt_GPG driver, this implementation should work on
 * Windows for operations requiring a passphrase (signing and decrypting). If
 * these requirements are not needed, it is recommended to use the native PHP
 * implementation as there are some drawbacks to the GnuPG driver.
 *
 * Drawbacks to using the GnuPG driver are:
 *
 * - some methods are not supported and the native PHP implementation is used
 *   as a fallback. Notably, {@link Crypt_GPG_Driver_GnuPG::exportPublicKey()}
 *   and {@link Crypt_GPG_Driver_GnuPG::deletePrivateKey()}.
 * - some methods do not provide as much information as the native PHP
 *   implementation. Specifically, the {@link Crypt_GPG_Driver_GnuPG::getKeys()}
 *   method does not return information about key algorithm, key length or
 *   whether or not a private key exists; and the
 *   {@link Crypt_GPG_Driver_GnuPG::verify()} method does not include the
 *   signature id in the returned signature object.
 * - installation of a PECL extension is required.
 * - detection of bad Open PGP data is not possible for the
 *   {@link Crypt_GPG_Driver_GnuPG::decrypt()} method.
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
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 * @link      http://www.gnupg.org/
 * @link      http://php.net/gnupg/
 */

/**
 * Crypt_GPG driver base class
 */
require_once 'Crypt/GPG.php';

/**
 * GPG signature helper class
 */
require_once 'Crypt/GPG/Signature.php';

/**
 * GPG exception classes
 */
require_once 'Crypt/GPG/Exceptions.php';

// {{{ class Crypt_GPG_Driver_GnuPG

/**
 * PECL gnupg Crypt_GPG driver
 *
 * This driver uses the gnupg PECL extension to control the GPG process. The
 * PECL extension must be installed and enabled for your PHP installation.
 *
 * If you have PECL installed, you can install the gnupg extension using:
 * <code>
 * $ pecl install gnupg
 * </code>
 * You will need to have the gpgme development libraries installed on your
 * system before building the PECL extension.
 *
 * Unlike the native PHP Crypt_GPG driver, this implementation should work on
 * Windows for operations requiring a passphrase (signing and decrypting). If
 * these requirements are not needed, it is recommended to use the native PHP
 * implementation as there are some drawbacks to the GnuPG driver.
 *
 * Drawbacks to using the GnuPG driver are:
 *
 * - some methods are not supported and the native PHP implementation is used
 *   as a fallback. Notably, {@link Crypt_GPG_Driver_GnuPG::exportPublicKey()}
 *   and {@link Crypt_GPG_Driver_GnuPG::deletePrivateKey()}.
 * - some methods do not provide as much information as the native PHP
 *   implementation. Specifically, the {@link Crypt_GPG_Driver_GnuPG::getKeys()}
 *   method does not return information about key algorithm, key length or
 *   whether or not a private key exists; and the
 *   {@link Crypt_GPG_Driver_GnuPG::verify()} method does not include the
 *   signature id in the returned signature object.
 * - installation of a PECL extension is required.
 * - detection of bad Open PGP data is not possible for the
 *   {@link Crypt_GPG_Driver_GnuPG::decrypt()} method.
 *
 * See the {@link http://php.net/gnupg PHP gnupg documentation} and
 * {@link http://pecl.php.net/package/gnupg PECL extension page}.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @link      http://www.gnupg.org/
 */
class Crypt_GPG_Driver_GnuPG extends Crypt_GPG
{
    // {{{ private class properties

    /**
     * The internal gnupg object used to control GPG
     *
     * @var gnupg
     */
    private $_gnupg;

    /**
     * Helper instance of the native PHP driver
     *
     * This is used to implement methods not supported by the PECL gnupg
     * extension.
     *
     * @var Crypt_GPG_Driver_Php
     */
    private $_gpg_helper;

    // }}}
    // {{{ __construct()

    /**
     * Creates a new GPG object that uses the gnupg PECL extension to control
     * the GPG process
     *
     * Developers are encouraged to use the {@link Crypt_GPG::factory()} method
     * to instantiate this class.
     *
     * Available options for this driver are:
     *
     * - string  homedir:    The directory where the GPG keyring files are
     *                       stored. If not specified, GPG uses the default of
     *                       $HOME/.gnupg, where $HOME is the present user's
     *                       home directory. This option only needs to be
     *                       specified when $HOME/.gnupg is inappropriate.
     *
     * @param array $options optional. An array of options used to create the
     *                       GPG object. All options must be optional and are
     *                       represented as key-value pairs.
     *
     * @throws PEAR_Exception if the gnupg PECL extension is missing or not
     *         loaded.
     */
    public function __construct(array $options = array())
    {
        if (!extension_loaded('gnupg')) {
            throw new PEAR_Exception('The gnupg PECL extension is required ' .
                'for this GPG driver.');
        }

        if (array_key_exists('homedir', $options)) {
            putenv('GNUPGHOME=' . (string)$options['homedir']);
        } else {
            // if homedir is not specified, always set GPG to the default
            // behavior.
            putenv('GNUPGHOME');
        }

        $this->_gnupg = new gnupg();

        $helper_options = array_intersect_key($options, array('homedir' => ''));
        $this->_gpg_helper = Crypt_GPG::factory('php', $helper_options);
    }

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
     * @throws Crypt_GPG_DuplicateKeyImportException if key is already in the
     *         keyring.
     *
     * @throws Crypt_GPG_NoDataException if the key data is missing or if the
     *         data is is not valid key data.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         File a bug report if these exceptions occur.
     */
    public function importKey($data)
    {
        $imported = $this->_gnupg->import($data);

        if ($imported === false) {
            throw new Crypt_GPG_Exception('Error importing GPG key: ' .
                $this->_gnupg->geterror());
        }

        if (!array_key_exists('fingerprint', $imported)) {
            throw new Crypt_GPG_NoDataException(
                'No valid GPG key data found.', Crypt_GPG::ERROR_NO_DATA);
        }

        $result = array(
            'fingerprint'       => $imported['fingerprint'],
            'public_imported'   => $imported['imported'],
            'public_unchanged'  => $imported['unchanged'],
            'private_imported'  => $imported['secretimported'],
            'private_unchanged' => $imported['secretunchanged']
        );

        return $result;
    }

    // }}}
    // {{{ exportPublicKey()

    /**
     * Exports a public key from the keyring
     *
     * The exported key remains on the keyring. To delete the public key, use
     * {@link Crypt_GPG::deletePublicKey()}.
     *
     * If more than one key fingerprint is available for the specified
     * <i>$key_id</i> (for example, if you use a non-unique uid) only the first
     * public key is exported.
     *
     * Since the gnupg PECL extension does not support exporting keys, this
     * method is handed off to the native PHP GPG driver.
     *
     * @param string  $key_id either the full uid of the public key, the email
     *                        part of the uid of the public key or the key id of
     *                        the public key. For example,
     *                        "Test User (example) <test@example.com>",
     *                        "test@example.com" or a hexadecimal string.
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
     *         File a bug report if these exceptions occur.
     */
    public function exportPublicKey($key_id, $armor = true)
    {
        return $this->_gpg_helper->exportPublicKey($key_id, $armor);
    }

    // }}}
    // {{{ deletePublicKey()

    /**
     * Deletes a public key from the keyring
     *
     * If more than one key fingerprint is available for the specified
     * <i>$key_id</i> (for example, if you use a non-unique uid) only the first
     * public key is deleted.
     *
     * @param string $key_id either the full uid of the public key, the email
     *                       part of the uid of the public key or the key id of
     *                       the public key. For example,
     *                       "Test User (example) <test@example.com>",
     *                       "test@example.com" or a hexadecimal string.
     *
     * @return void
     *
     * @throws Crypt_GPG_KeyNotFoundException if a private key with the given
     *         <i>$key_id</i> is not found.
     *
     * @throws Crypt_GPG_DeletePrivateKeyException if the specified public key
     *         has an associated private key on the keyring. The private key
     *         must be deleted first.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         File a bug report if these exceptions occur.
     */
    public function deletePublicKey($key_id)
    {
        $fingerprint = $this->getFingerprint($key_id);
        if ($this->_gnupg->deletekey($key_id) === false) {
            $error = $this->_gnupg->geterror();
            switch ($error) {
            case 'delete failed':
                throw new Crypt_GPG_DeletePrivateKeyException(
                    'Private key must be deleted before public key can be ' .
                    'deleted.', Crypt_GPG::ERROR_DELETE_PRIVATE_KEY, $key_id);

                break;
            case 'get_key failed':
                throw new Crypt_GPG_KeyNotFoundException(
                    'Public key not found: ' . $key_id,
                    Crypt_GPG::ERROR_KEY_NOT_FOUND, $key_id);

                break;
            default:
                throw new Crypt_GPG_Exception(
                    'Unknown error deleting public key: ' . $error);

                break;
            }
        }
    }

    // }}}
    // {{{ deletePrivateKey()

    /**
     * Deletes a private key from the keyring
     *
     * If more than one key fingerprint is available for the specified
     * <i>$key_id</i> (for example, if you use a non-unique uid) only the first
     * private key is deleted.
     *
     * Since the gnupg PECL extension does not support deleting private keys
     * without also deleting the associated public keys, this method is handed
     * off to the native PHP GPG driver.
     *
     * @param string $key_id either the full uid of the private key, the email
     *                       part of the uid of the private key or the key id of
     *                       the private key. For example,
     *                       "Test User (example) <test@example.com>",
     *                       "test@example.com" or a hexadecimal string.
     *
     * @return void
     *
     * @throws Crypt_GPG_KeyNotFoundException if a private key with the given
     *         <i>$key_id</i> is not found.
     *
     * @throws Crypt_GPG_Exception if an unknown or unexpected error occurs.
     *         File a bug report if these exceptions occur.
     */
    public function deletePrivateKey($key_id)
    {
        return $this->_gpg_helper->deletePrivateKey($key_id);
    }

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
     *         File a bug report if these exceptions occur.
     *
     * @see Crypt_GPG_Key
     */
    public function getKeys($key_id = '')
    {
        $keys = array();

        $info = $this->_gnupg->keyinfo($key_id);

        if ($info === false) {
            throw new Crypt_GPG_Exception('Unknown error getting keys: ' .
                $this->_gnupg->geterror());
        }

        foreach ($info as $key_info) {
            $key = new Crypt_GPG_Key();
            foreach ($key_info['uids'] as $key_user_id) {
                $user_id = new Crypt_GPG_UserId();
                $user_id->setName($key_user_id['name']);
                $user_id->setComment($key_user_id['comment']);
                $user_id->setEmail($key_user_id['email']);
                $user_id->setRevoked($key_user_id['revoked']);
                $user_id->setValid(!$key_user_id['invalid']);
                $key->addUserId($user_id);
            }
            foreach ($key_info['subkeys'] as $key_sub_key) {
                $sub_key = new Crypt_GPG_SubKey();
                $sub_key->setId($key_sub_key['keyid']);
                $sub_key->setFingerprint($key_sub_key['fingerprint']);
                $sub_key->setCreationDate(intval($key_sub_key['timestamp']));
                $sub_key->setCanSign($key_sub_key['can_sign']);
                $sub_key->setCanEncrypt($key_sub_key['can_encrypt']);
                $key->addSubKey($sub_key);
            }
            $keys[] = $key;
        }

        return $keys;
    }

    // }}}
    // {{{ getFingerprint()

    /**
     * Gets a key fingerprint from the keyring
     *
     * If more than one key fingerprint is available (for example, if you use
     * a non-unique user id) only the first key fingerprint is returned.
     *
     * @param string  $key_id either the full user id of the key, the email
     *                        part of the user id of the key, or the key id of
     *                        the key. For example,
     *                        "Test User (example) <test@example.com>",
     *                        "test@example.com" or a hexadecimal string.
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
     *         File a bug report if these exceptions occur.
     */
    public function getFingerprint($key_id, $format = Crypt_GPG::FORMAT_NONE)
    {
        $fingerprint = null;

        $info = $this->_gnupg->keyinfo($key_id);

        if ($info === false) {
            throw new Crypt_GPG_Exception(
                'Unknown error getting key fingerprint: ' .
                $this->_gnupg->geterror());
        }

        if (count($info) > 0 && count($info[0]['subkeys']) > 0) {
            $fingerprint = $info[0]['subkeys'][0]['fingerprint'];

            switch ($format) {
            case Crypt_GPG::FORMAT_CANONICAL:
                $fingerprint_exp = str_split($fingerprint, 4);
                $format          = '%s %s %s %s %s  %s %s %s %s %s';
                $fingerprint     = vsprintf($format, $fingerprint_exp);
                break;

            case Crypt_GPG::FORMAT_X509:
                $fingerprint_exp = str_split($fingerprint, 2);
                $fingerprint     = implode(':', $fingerprint_exp);
                break;
            }
        }

        return $fingerprint;
    }

    // }}}
    // {{{ encrypt()

    /**
     * Encrypts string data
     *
     * Data is ASCII armored by default but may optionally be returned as
     * binary.
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
     *         File a bug report if these exceptions occur.
     *
     * @sensitive $data
     */
    public function encrypt($key_id, $data, $armor = true)
    {
        $this->_gnupg->addencryptkey($key_id);
        $this->_gnupg->setarmor($armor);
        $encrypted_data = $this->_gnupg->encrypt($data);
        $this->_gnupg->clearencryptkeys();

        if ($encrypted_data === false) {
            $error = $this->_gnupg->geterror();
            switch ($error) {
            case 'no key for encryption set':
                throw new Crypt_GPG_KeyNotFoundException(
                    "Data could not be encrypted because key '" . $key_id .
                    "' was not found.",
                    Crypt_GPG::ERROR_KEY_NOT_FOUND, $key_id);

                break;
            default:
                throw new Crypt_GPG_Exception(
                    'Unknown error encrypting data: ' . $error);

                break;
            }
        }

        return $encrypted_data;
    }

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
     *         File a bug report if these exceptions occur.
     *
     * @sensitive $passphrase
     */
    public function decrypt($encrypted_data, $passphrase = null)
    {
        // try to decrypt using all available encryption keys
        foreach ($this->_gnupg->keyinfo('') as $key) {
            if ($key['can_encrypt']) {
                foreach ($key['subkeys'] as $subkey) {
                    if ($subkey['can_encrypt']) {
                        $this->_gnupg->adddecryptkey($subkey['fingerprint'],
                            $passphrase);
                    }
                }
            }
        }

        $decrypted_data = $this->_gnupg->decrypt($encrypted_data);

        $this->_gnupg->cleardecryptkeys();

        if ($decrypted_data === false) {
            $error = $this->_gnupg->geterror();
            switch ($error) {
            case 'get_key failed':
                throw new Crypt_GPG_KeyNotFoundException(
                    'Cannot decrypt data. Private key required for decryption '.
                    'is not in the keyring. Import the private key before '.
                    'trying to decrypt this data.',
                    Crypt_GPG::ERROR_KEY_NOT_FOUND);

                break;
            case 'Incorrent passphrase':
                if ($passphrase === null) {
                    throw new Crypt_GPG_BadPassphraseException(
                        'Cannot decrypt data. No passphrase provided.',
                        Crypt_GPG::ERROR_MISSING_PASSPHRASE);
                } else {
                    throw new Crypt_GPG_BadPassphraseException(
                        'Cannot decrypt data. Incorrect passphrase provided.',
                        Crypt_GPG::ERROR_BAD_PASSPHRASE);
                }

                break;
            default:
                throw new Crypt_GPG_Exception(
                    'Unknown error decrypting data: ' . $error);

                break;
            }
        }

        return $decrypted_data;
    }

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
     *                            "test@example.com" or a hexadecimal string.
     * @param string  $data       the data to be signed.
     * @param string  $passphrase optional. The passphrase of the private key
     *                            used to sign the data. Only required if the
     *                            private key requires a passphrase. Specify
     *                            null for no passphrase.
     * @param boolean $mode       optional. The data signing mode to use. Should
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
     *         file a bug report if these exceptions occur.
     *
     * @sensitive $passphrase
     */
    public function sign($key_id, $data, $passphrase = null,
        $mode = Crypt_GPG::SIGN_MODE_NORMAL, $armor = true)
    {
        $this->_gnupg->addsignkey($key_id, $passphrase);

        $mode_map = array(
            Crypt_GPG::SIGN_MODE_NORMAL   => gnupg::SIG_MODE_NORMAL,
            Crypt_GPG::SIGN_MODE_CLEAR    => gnupg::SIG_MODE_CLEAR,
            Crypt_GPG::SIGN_MODE_DETACHED => gnupg::SIG_MODE_DETACH
        );

        $this->_gnupg->setarmor($armor);
        $this->_gnupg->setsignmode($mode_map[$mode]);
        $signed_data = $this->_gnupg->sign($data);
        $this->_gnupg->clearsignkeys();

        if ($signed_data === false) {
            $error = $this->_gnupg->geterror();
            switch ($error) {
            case 'no passphrase set':
                throw new Crypt_GPG_KeyNotFoundException(
                    'Cannot sign data. Private key not found. Import the '.
                    'private key before trying to sign data.',
                    Crypt_GPG::ERROR_KEY_NOT_FOUND);

            case 'Incorrent passphrase':
                if ($passphrase === null) {
                    throw new Crypt_GPG_BadPassphraseException(
                        'Cannot sign data. No passphrase provided.',
                        Crypt_GPG::ERROR_MISSING_PASSPHRASE);
                } else {
                    throw new Crypt_GPG_BadPassphraseException(
                        'Cannot sign data. Incorrect passphrase provided.',
                        Crypt_GPG::ERROR_BAD_PASSPHRASE);
                }

                break;
            default:
                throw new Crypt_GPG_Exception(
                    'Unknown error signing data: ' . $error);

                break;
            }
        }

        return $signed_data;
    }
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
     * @see Crypt_GPG_Signature
     */
    public function verify($signed_data, $signature = '')
    {
        if ($signature == '') {
            $gnupg_sig = $this->_gnupg->verify($signed_data, false);
        } else {
            $gnupg_sig = $this->_gnupg->verify($signed_data, $signature);
        }

        if ($gnupg_sig === false) {
            throw new Crypt_GPG_NoDataException(
                'No valid signature data found.', Crypt_GPG::ERROR_NO_DATA);
        }

        $sig = new Crypt_GPG_Signature();
        $sig->setKeyFingerprint($gnupg_sig[0]['fingerprint']);
        $sig->setCreationDate($gnupg_sig[0]['timestamp']);
        $sig->setIsValid(intval($gnupg_sig[0]['summary']) |
            gnupg::SIGSUM_VALID == gnupg::SIGSUM_VALID);

        $keys = $this->getKeys($sig->getKeyFingerprint());
        if (count($keys) > 0) {
            $user_ids = $keys[0]->getUserIds();
            if (count($user_ids) > 0) {
                $sig->setUserId($user_ids[0]);
            }
        }

        return $sig;
    }

    // }}}
}

// }}}

?>
