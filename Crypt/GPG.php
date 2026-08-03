<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt;

use Crypt\GPG\Engine;
use Crypt\GPG\Exceptions;
use Crypt\GPG\Key;
use Crypt\GPG\KeyEditor;
use Crypt\GPG\Signature;
use Crypt\GPG\SubKey;
use Crypt\GPG\UserId;

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
 * @copyright 2005-2013 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 * @link      https://www.gnupg.org/
 */
class GPG
{
    /**
     * Signing mode for normal signing of data. The signed message will not
     * be readable without special software.
     *
     * This is the default signing mode.
     *
     * @see self::sign()
     * @see self::signFile()
     */
    public const SIGN_MODE_NORMAL = 1;

    /**
     * Signing mode for clearsigning data. Clearsigned signatures are ASCII
     * armored data and are readable without special software. If the signed
     * message is unencrypted, the message will still be readable. The message
     * text will be in the original encoding.
     *
     * @see self::sign()
     * @see self::signFile()
     */
    public const SIGN_MODE_CLEAR = 2;

    /**
     * Signing mode for creating a detached signature. When using detached
     * signatures, only the signature data is returned. The original message
     * text may be distributed separately from the signature data. This is
     * useful for miltipart/signed email messages as per
     * {@link http://www.ietf.org/rfc/rfc3156.txt RFC 3156}.
     *
     * @see self::sign()
     * @see self::signFile()
     */
    public const SIGN_MODE_DETACHED = 3;

    /**
     * No formatting is performed.
     *
     * Example: C3BC615AD9C766E5A85C1F2716D27458B1BBA1C4
     *
     * @see self::getFingerprint()
     */
    public const FORMAT_NONE = 1;

    /**
     * Fingerprint is formatted in the format used by the GnuPG gpg command's
     * default output.
     *
     * Example: C3BC 615A D9C7 66E5 A85C  1F27 16D2 7458 B1BB A1C4
     *
     * @see self::getFingerprint()
     */
    public const FORMAT_CANONICAL = 2;

    /**
     * Fingerprint is formatted in the format used when displaying X.509 certificates
     *
     * Example: C3:BC:61:5A:D9:C7:66:E5:A8:5C:1F:27:16:D2:74:58:B1:BB:A1:C4
     *
     * @see self::getFingerprint()
     */
    public const FORMAT_X509 = 3;

    /**
     * Use to specify ASCII armored mode for returned data
     */
    public const ARMOR_ASCII = true;

    /**
     * Use to specify binary mode for returned data
     */
    public const ARMOR_BINARY = false;

    /**
     * Use to specify that line breaks in signed text should be normalized
     */
    public const TEXT_NORMALIZED = true;

    /**
     * Use to specify that line breaks in signed text should not be normalized
     */
    public const TEXT_RAW = false;

    /**
     * Error code returned when there is no error.
     */
    public const ERROR_NONE = 0;

    /**
     * Error code returned when an unknown or unhandled error occurs.
     */
    public const ERROR_UNKNOWN = 1;

    /**
     * Error code returned when a bad passphrase is used.
     */
    public const ERROR_BAD_PASSPHRASE = 2;

    /**
     * Error code returned when a required passphrase is missing.
     */
    public const ERROR_MISSING_PASSPHRASE = 3;

    /**
     * Error code returned when a key that is already in the keyring is imported.
     */
    public const ERROR_DUPLICATE_KEY = 4;

    /**
     * Error code returned the required data is missing for an operation.
     *
     * This could be missing key data, missing encrypted data or missing
     * signature data.
     */
    public const ERROR_NO_DATA = 5;

    /**
     * Error code returned when an unsigned key is used.
     */
    public const ERROR_UNSIGNED_KEY = 6;

    /**
     * Error code returned when a key that is not self-signed is used.
     */
    public const ERROR_NOT_SELF_SIGNED = 7;

    /**
     * Error code returned when a public or private key that is not in the
     * keyring is used.
     */
    public const ERROR_KEY_NOT_FOUND = 8;

    /**
     * Error code returned when an attempt to delete public key having a
     * private key is made.
     */
    public const ERROR_DELETE_PRIVATE_KEY = 9;

    /**
     * Error code returned when one or more bad signatures are detected.
     */
    public const ERROR_BAD_SIGNATURE = 10;

    /**
     * Error code returned when there is a problem reading GnuPG data files.
     */
    public const ERROR_FILE_PERMISSIONS = 11;

    /**
     * Error code returned when a key could not be created.
     */
    public const ERROR_KEY_NOT_CREATED = 12;

    /**
     * Error code returned when bad key parameters are used during key generation.
     */
    public const ERROR_BAD_KEY_PARAMS = 13;

    /**
     * URI at which package bugs may be reported.
     */
    public const BUG_URI = 'https://github.com/pear/Crypt_GPG/issues';

    /**
     * Engine used to control the GPG subprocess
     *
     * @var Engine
     *
     * @see self::setEngine()
     */
    protected $engine = null;

    /**
     * Keys used to encrypt
     *
     * The array is of the form:
     * <code>
     * [
     *   $key_id => [
     *     'fingerprint' => $fingerprint,
     *     'passphrase'  => null
     *   ]
     * ];
     * </code>
     *
     * @var array
     * @see self::addEncryptKey()
     * @see self::clearEncryptKeys()
     */
    protected $encryptKeys = [];

    /**
     * Keys used to decrypt
     *
     * The array is of the form:
     * <code>
     * [
     *   $key_id => [
     *     'fingerprint' => $fingerprint,
     *     'passphrase'  => $passphrase
     *   ]
     * ];
     * </code>
     *
     * @var array
     * @see self::addSignKey()
     * @see self::clearSignKeys()
     */
    protected $signKeys = [];

    /**
     * Keys used to sign
     *
     * The array is of the form:
     * <code>
     * [
     *   $key_id => [
     *     'fingerprint' => $fingerprint,
     *     'passphrase'  => $passphrase
     *   ]
     * ];
     * </code>
     *
     * @var array
     * @see self::addDecryptKey()
     * @see self::clearDecryptKeys()
     */
    protected $decryptKeys = [];

    /**
     * Passphrases used on import/export of private keys
     *
     * The array is of the form:
     * <code>
     * [$key_id => $passphrase];
     * </code>
     *
     * @var array
     * @see self::addPassphrase()
     * @see self::clearPassphrases()
     */
    protected $passphrases = [];


    /**
     * Creates a new GPG object
     *
     * Available options are:
     *
     * - <kbd>string homedir</kbd> - the directory where the GPG keyring files are
     *                      stored. If not specified, Crypt_GPG uses the default
     *                      of <kbd>~/.gnupg</kbd>.
     * - <kbd>string publicKeyring</kbd> - the file path of the public keyring.
     *                      Use this if the public keyring is not in the homedir,
     *                      or if the keyring is in a directory not writable
     *                      by the process invoking GPG (like Apache). Then you
     *                      can specify the path to the keyring with this option
     *                      (/foo/bar/pubring.gpg), and specify a writable directory
     *                      (like /tmp) using the <i>homedir</i> option.
     * - <kbd>string privateKeyring</kbd> - the file path of the private keyring.
     *                      Use this if the private keyring is not in the homedir,
     *                      or if the keyring is in a directory not writable
     *                      by the process invoking GPG (like Apache). Then
     *                      you can specify the path to the keyring with this option
     *                      (/foo/bar/secring.gpg), and specify a writable directory
     *                      (like /tmp) using the <i>homedir</i> option.
     * - <kbd>string trustDb</kbd> - the file path of the web-of-trust database.
     *                      Use this if the trust database is not in the homedir, or
     *                      if the database is in a directory not writable
     *                      by the process invoking GPG (like Apache). Then you can
     *                      specify the path to the trust database with this option
     *                      (/foo/bar/trustdb.gpg), and specify a writable directory
     *                      (like /tmp) using the <i>homedir</i> option.
     * - <kbd>string binary</kbd> - the location of the GPG binary.
     *                      If not specified, the driver attempts to auto-detect
     *                      the GPG binary location using a list of known default
     *                      locations for the current operating system. The option
     *                      <kbd>gpgBinary</kbd> is a deprecated alias.
     * - <kbd>string digest-algo</kbd> - Sets the message digest algorithm.
     * - <kbd>string cipher-algo</kbd> - Sets the symmetric cipher.
     * - <kbd>string compress-algo</kbd> - Sets the compression algorithm.
     * - <kbd>bool   strict</kbd> - In strict mode clock problems on subkeys
     *                      and signatures are not ignored (--ignore-time-conflict
     *                      and --ignore-valid-from options).
     * - <kbd>mixed debug</kbd> - whether or not to use debug mode.
     *                      When debug mode is on, all communication to and from
     *                      the GPG subprocess is logged. This can be useful to
     *                      diagnose errors when using Crypt_GPG.
     * - <kbd>array options</kbd> - additional per-command options to the GPG
     *                      command. Key of the array is a command (e.g.
     *                      gen-key, import, sign, encrypt, list-keys).
     *                      Value is a string containing command line arguments to be
     *                      added to the related command. For example:
     *                      ['sign' => '--emit-version'].
     *
     * @param array $options optional. An array of options used to create the
     *                       GPG object. All options are optional and are
     *                       represented as key-value pairs.
     *
     * @throws Exceptions\FileException if the <kbd>homedir</kbd> does not exist
     *         and cannot be created. This can happen if <kbd>homedir</kbd> is
     *         not specified, Crypt_GPG is run as the web user, and the web
     *         user has no home directory. This exception is also thrown if any
     *         of the options <kbd>publicKeyring</kbd>,
     *         <kbd>privateKeyring</kbd> or <kbd>trustDb</kbd> options are
     *         specified but the files do not exist or are are not readable.
     *         This can happen if the user running the Crypt_GPG process (for
     *         example, the Apache user) does not have permission to read the
     *         files.
     *
     * @throws Exceptions\Exception if the provided <kbd>binary</kbd> is invalid, or
     *         if no <kbd>binary</kbd> is provided and no suitable binary could
     *         be found.
     */
    public function __construct(array $options = [])
    {
        $this->setEngine(new Engine($options));
    }

    /**
     * Get a key editor instance
     */
    public function getKeyEditor(): KeyEditor
    {
        return $this->engine->getKeyEditor();
    }

    /**
     * Imports a public or private key into the keyring
     *
     * Keys may be removed from the keyring using
     * {@link self::deletePublicKey()} or {@link self::deletePrivateKey()}.
     *
     * @param string $data the key data to be imported.
     *
     * @return array an associative array containing the following elements:
     *               - <kbd>fingerprint</kbd>       - the fingerprint of the
     *                                                imported key,
     *               - <kbd>public_imported</kbd>   - the number of public
     *                                                keys imported,
     *               - <kbd>public_unchanged</kbd>  - the number of unchanged
     *                                                public keys,
     *               - <kbd>private_imported</kbd>  - the number of private
     *                                                keys imported,
     *               - <kbd>private_unchanged</kbd> - the number of unchanged
     *                                                private keys.
     *
     * @throws Exceptions\NoDataException if the key data is missing or if the
     *         data is is not valid key data.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addPassphrase()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     *
     * @see self::addPassphrase()
     * @see self::clearPassphrases()
     */
    public function importKey($data): array
    {
        return $this->_importKey($data, false);
    }

    /**
     * Imports a public or private key file into the keyring
     *
     * Keys may be removed from the keyring using
     * {@link self::deletePublicKey()} or {@link self::deletePrivateKey()}.
     *
     * @param string $filename the key file to be imported.
     *
     * @return array an associative array containing the following elements:
     *               - <kbd>fingerprint</kbd>       - the fingerprint of the
     *                                                imported key,
     *               - <kbd>public_imported</kbd>   - the number of public
     *                                                keys imported,
     *               - <kbd>public_unchanged</kbd>  - the number of unchanged
     *                                                public keys,
     *               - <kbd>private_imported</kbd>  - the number of private
     *                                                keys imported,
     *               - <kbd>private_unchanged</kbd> - the number of unchanged
     *                                                private keys.
     *                                                  private keys.
     *
     * @throws Exceptions\NoDataException if the key data is missing or if the
     *         data is is not valid key data.
     *
     * @throws Exceptions\FileException if the key file is not readable.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addPassphrase()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function importKeyFile($filename): array
    {
        return $this->_importKey($filename, true);
    }

    /**
     * Exports a private key from the keyring
     *
     * The exported key remains on the keyring. To delete the key, use
     * {@link self::deletePrivateKey()}.
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first private key is exported.
     *
     * @param string  $keyId either the full uid of the private key, the email
     *                       part of the uid of the private key or the key id of
     *                       the private key. For example,
     *                       "Test User (example) <test@example.com>",
     *                       "test@example.com" or a hexadecimal string.
     * @param bool    $armor optional. If true, ASCII armored data is returned;
     *                       otherwise, binary data is returned. Defaults to
     *                       true.
     *
     * @return string the private key data.
     *
     * @throws Exceptions\KeyNotFoundException if a private key with the given
     *         <kbd>$keyId</kbd> is not found.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addPassphrase()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function exportPrivateKey($keyId, $armor = true): string
    {
        return $this->_exportKey($keyId, $armor, true);
    }

    /**
     * Exports a public key from the keyring
     *
     * The exported key remains on the keyring. To delete the public key, use
     * {@link self::deletePublicKey()}.
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first public key is exported.
     *
     * @param string  $keyId either the full uid of the public key, the email
     *                       part of the uid of the public key or the key id of
     *                       the public key. For example,
     *                       "Test User (example) <test@example.com>",
     *                       "test@example.com" or a hexadecimal string.
     * @param bool    $armor optional. If true, ASCII armored data is returned;
     *                       otherwise, binary data is returned. Defaults to
     *                       true.
     *
     * @return string the public key data.
     *
     * @throws Exceptions\KeyNotFoundException if a public key with the given
     *         <kbd>$keyId</kbd> is not found.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function exportPublicKey($keyId, $armor = true): string
    {
        return $this->_exportKey($keyId, $armor, false);
    }

    /**
     * Deletes a public key from the keyring
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first public key is deleted.
     *
     * @param Key|string $keyId Either the {@link Crypt\GPG\Key} object or full uid of the public key,
     *                          the email part of the uid of the public key or the key id of
     *                          the public key. For example "Test User (example) <test@example.com>",
     *                          "test@example.com" or a hexadecimal string.
     *
     * @throws Exceptions\KeyNotFoundException if a public key with the given
     *         <kbd>$keyId</kbd> is not found.
     *
     * @throws Exceptions\DeletePrivateKeyException if the specified public key
     *         has an associated private key on the keyring. The private key
     *         must be deleted first (when using GnuPG < 2.1).
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function deletePublicKey($keyId): void
    {
        $fingerprint = $this->toFingerprint($keyId);

        $operation = '--delete-key -- ' . escapeshellarg($fingerprint);
        $arguments = [
            '--batch',
            '--yes',
        ];

        $this->engine->reset();
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();
    }

    /**
     * Deletes a private key from the keyring
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first private key is deleted.
     *
     * Calls GPG with the <kbd>--delete-secret-key</kbd> command.
     *
     * @param Key|string $keyId Either the {@link Crypt\GPG\Key} object or full uid of the public key,
     *                          the email part of the uid of the public key or the key id of
     *                          the public key. For example "Test User (example) <test@example.com>",
     *                          "test@example.com" or a hexadecimal string.
     *
     * @throws Exceptions\KeyNotFoundException if a private key with the given
     *         <kbd>$keyId</kbd> is not found.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function deletePrivateKey($keyId): void
    {
        $fingerprint = $this->toFingerprint($keyId);

        $operation = '--delete-secret-key -- ' . escapeshellarg($fingerprint);
        $arguments = [
            '--batch',
            '--yes',
        ];

        $this->engine->reset();
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();
    }

    /**
     * Gets the available keys in the keyring
     *
     * Calls GPG with the <kbd>--list-keys</kbd> command and grabs keys. See
     * the first section of <b>doc/DETAILS</b> in the
     * {@link http://www.gnupg.org/download/ GPG package} for a detailed
     * description of how the GPG command output is parsed.
     *
     * @param string $keyId optional. Only keys with that match the specified
     *                      pattern are returned. The pattern may be part of
     *                      a user id, a key id or a key fingerprint. If not
     *                      specified, all keys are returned.
     *
     * @return array<Key> A list of keys. If no keys match the specified <kbd>$keyId</kbd>
     *                    an empty array is returned.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function getKeys($keyId = ''): array
    {
        return $this->_getKeys($keyId);
    }

    /**
     * Gets a key fingerprint from the keyring
     *
     * If more than one key fingerprint is available (for example, if you use
     * a non-unique user id) only the first key fingerprint is returned.
     *
     * Calls the GPG <kbd>--list-keys</kbd> command with the
     * <kbd>--with-fingerprint</kbd> option to retrieve a public key
     * fingerprint.
     *
     * @param string  $keyId  either the full user id of the key, the email
     *                        part of the user id of the key, or the key id of
     *                        the key. For example,
     *                        "Test User (example) <test@example.com>",
     *                        "test@example.com" or a hexadecimal string.
     * @param int     $format optional. How the fingerprint should be formatted.
     *                        Use {@link self::FORMAT_X509} for X.509
     *                        certificate format,
     *                        {@link self::FORMAT_CANONICAL} for the format
     *                        used by GnuPG output and
     *                        {@link self::FORMAT_NONE} for no formatting.
     *                        Defaults to <code>self::FORMAT_NONE</code>.
     *
     * @return string|null The fingerprint of the key, or null if no fingerprint
     *                     is found for the given <kbd>$keyId</kbd>.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function getFingerprint($keyId, $format = self::FORMAT_NONE): ?string
    {
        $output    = '';
        $operation = '--list-keys -- ' . escapeshellarg($keyId);
        $arguments = [
            '--with-colons',
            '--with-fingerprint',
        ];

        $this->engine->reset();
        $this->engine->setOutput($output);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        $fingerprint = null;

        foreach (explode(PHP_EOL, $output) as $line) {
            if (str_starts_with($line, 'fpr')) {
                $lineExp     = explode(':', $line);
                $fingerprint = $lineExp[9];

                switch ($format) {
                    case self::FORMAT_CANONICAL:
                        $fingerprintExp = str_split($fingerprint, 4);
                        $format         = '%s %s %s %s %s  %s %s %s %s %s';
                        $fingerprint    = vsprintf($format, $fingerprintExp);
                        break;

                    case self::FORMAT_X509:
                        $fingerprintExp = str_split($fingerprint, 2);
                        $fingerprint    = implode(':', $fingerprintExp);
                        break;
                }

                break;
            }
        }

        return $fingerprint;
    }

    /**
     * Get information about the last signature that was created.
     */
    public function getLastSignatureInfo(): ?\Crypt\GPG\SignatureCreationInfo
    {
        return $this->engine->getProcessData('SignatureInfo');
    }

    /**
     * Encrypts string data
     *
     * Data is ASCII-armored by default, but may optionally be returned as binary.
     *
     * @param string  $data  the data to be encrypted.
     * @param bool    $armor optional. If true, ASCII armored data is returned;
     *                       otherwise, binary data is returned. Defaults to true.
     *
     * @return string the encrypted data.
     *
     * @throws Exceptions\KeyNotFoundException if no encryption key is specified.
     *         See {@link self::addEncryptKey()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     *
     * @sensitive $data
     */
    public function encrypt($data, $armor = self::ARMOR_ASCII): string
    {
        return $this->_encrypt($data, false, null, $armor);
    }

    /**
     * Encrypts a file
     *
     * Encrypted data is ASCII-armored by default, but may optionally be saved as binary.
     *
     * @param string  $filename      the filename of the file to encrypt.
     * @param string  $encryptedFile optional. The filename of the file in
     *                               which to store the encrypted data. If null
     *                               or unspecified, the encrypted data is
     *                               returned as a string.
     * @param bool    $armor         optional. If true, ASCII armored data is
     *                               returned; otherwise, binary data is
     *                               returned. Defaults to true.
     *
     * @return string|null If the <kbd>$encryptedFile</kbd> parameter is null,
     *                     a string containing the encrypted data is returned.
     *
     * @throws Exceptions\KeyNotFoundException if no encryption key is specified.
     *         See {@link self::addEncryptKey()}.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function encryptFile($filename, $encryptedFile = null, $armor = self::ARMOR_ASCII): ?string
    {
        return $this->_encrypt($filename, true, $encryptedFile, $armor);
    }

    /**
     * Encrypts and signs data
     *
     * Data is encrypted and signed in a single pass.
     *
     * @param string $data  The data to be encrypted and signed.
     * @param bool   $armor Optional. If true, ASCII armored data is returned;
     *                      otherwise, binary data is returned. Defaults to
     *                      true.
     *
     * @return string The encrypted signed data.
     *
     * @throws Exceptions\KeyNotFoundException if no encryption key is specified
     *         or if no signing key is specified. See
     *         {@link self::addEncryptKey()} and
     *         {@link self::addSignKey()}.
     *
     * @throws Exceptions\BadPassphraseException if a specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     *
     * @see self::decryptAndVerify()
     */
    public function encryptAndSign($data, $armor = self::ARMOR_ASCII): string
    {
        return $this->_encryptAndSign($data, false, null, $armor);
    }

    /**
     * Encrypts and signs a file
     *
     * The file is encrypted and signed in a single pass.
     *
     * @param string  $filename   the name of the file containing the data to
     *                            be encrypted and signed.
     * @param string  $signedFile optional. The name of the file in which the
     *                            encrypted, signed data should be stored. If
     *                            null or unspecified, the encrypted, signed
     *                            data is returned as a string.
     * @param bool    $armor      optional. If true, ASCII armored data is
     *                            returned; otherwise, binary data is returned.
     *                            Defaults to true.
     *
     * @return string|null if the <kbd>$signedFile</kbd> parameter is null, a
     *                     string containing the encrypted, signed data is returned.
     *
     * @throws Exceptions\KeyNotFoundException if no encryption key is specified
     *         or if no signing key is specified. See
     *         {@link self::addEncryptKey()} and {@link self::addSignKey()}.
     *
     * @throws Exceptions\BadPassphraseException if a specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     *
     * @see self::decryptAndVerifyFile()
     */
    public function encryptAndSignFile($filename, $signedFile = null, $armor = self::ARMOR_ASCII): ?string
    {
        return $this->_encryptAndSign($filename, true, $signedFile, $armor);
    }

    /**
     * Decrypts string data
     *
     * This method assumes the required private key is available in the keyring
     * and throws an exception if the private key is not available. To add a
     * private key to the keyring, use the {@link self::importKey()} or
     * {@link self::importKeyFile()} methods.
     *
     * @param string $encryptedData the data to be decrypted.
     *
     * @return string the decrypted data.
     *
     * @throws Exceptions\KeyNotFoundException if the private key needed to
     *         decrypt the data is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if specified data does not contain
     *         GPG encrypted data.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addDecryptKey()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function decrypt($encryptedData): string
    {
        return $this->_decrypt($encryptedData, false, null);
    }

    /**
     * Decrypts a file
     *
     * This method assumes the required private key is available in the keyring
     * and throws an exception if the private key is not available. To add a
     * private key to the keyring, use the {@link self::importKey()} or
     * {@link self::importKeyFile()} methods.
     *
     * @param string $encryptedFile the name of the encrypted file data to
     *                              decrypt.
     * @param string $decryptedFile optional. The name of the file to which the
     *                              decrypted data should be written. If null
     *                              or unspecified, the decrypted data is
     *                              returned as a string.
     *
     * @return string|null if the <kbd>$decryptedFile</kbd> parameter is null,
     *                     a string containing the decrypted data is returned.
     *
     * @throws Exceptions\KeyNotFoundException if the private key needed to
     *         decrypt the data is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if specified data does not contain
     *         GPG encrypted data.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addDecryptKey()}.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function decryptFile($encryptedFile, $decryptedFile = null): ?string
    {
        return $this->_decrypt($encryptedFile, true, $decryptedFile);
    }

    /**
     * Decrypts and verifies string data
     *
     * This method assumes the required private key is available in the keyring
     * and throws an exception if the private key is not available. To add a
     * private key to the keyring, use the {@link self::importKey()} or
     * {@link self::importKeyFile()} methods.
     *
     * @param string  $encryptedData      the encrypted, signed data to be decrypted
     *                                    and verified.
     * @param bool    $ignoreVerifyErrors enables ignoring of signature
     *                                    verification errors caused by missing public key
     *                                    When enabled \Crypt\GPG\KeyNotFoundException
     *                                    will not be thrown.
     *
     * @return array two element array. The array has an element 'data'
     *               containing the decrypted data and an element
     *               'signatures' containing an array of
     *               {@link \Crypt\GPG\Signature} objects for the signed data.
     *
     * @throws Exceptions\KeyNotFoundException if the private key needed to
     *         decrypt the data or the public key to verify the signature
     *         is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if specified data does not contain
     *         GPG encrypted data.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addDecryptKey()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function decryptAndVerify($encryptedData, $ignoreVerifyErrors = false): array
    {
        return $this->_decryptAndVerify($encryptedData, false, null, $ignoreVerifyErrors);
    }

    /**
     * Decrypts and verifies a signed, encrypted file
     *
     * This method assumes the required private key is available in the keyring
     * and throws an exception if the private key is not available. To add a
     * private key to the keyring, use the {@link self::importKey()} or
     * {@link self::importKeyFile()} methods.
     *
     * @param string  $encryptedFile      the name of the signed, encrypted file to
     *                                    to decrypt and verify.
     * @param string  $decryptedFile      optional. The name of the file to which the
     *                                    decrypted data should be written. If null
     *                                    or unspecified, the decrypted data is
     *                                    returned in the results array.
     * @param bool    $ignoreVerifyErrors enables ignoring of signature
     *                                    verification errors caused by missing public key
     *                                    When enabled \Crypt\GPG\KeyNotFoundException
     *                                    will not be thrown.
     *
     * @return array two element array. The array has an element 'data'
     *               containing the decrypted data and an element
     *               'signatures' containing an array of
     *               {@link \Crypt\GPG\Signature} objects for the signed data.
     *               If the decrypted data is written to a file, the 'data'
     *               element is null.
     *
     * @throws Exceptions\KeyNotFoundException if the private key needed to
     *         decrypt the data or the public key to verify the signature
     *         is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if specified data does not contain
     *         GPG encrypted data.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addDecryptKey()}.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function decryptAndVerifyFile($encryptedFile, $decryptedFile = null, $ignoreVerifyErrors = false): array
    {
        return $this->_decryptAndVerify($encryptedFile, true, $decryptedFile, $ignoreVerifyErrors);
    }

    /**
     * Sets the I/O engine to use for GnuPG operations
     *
     * Normally this method does not need to be used. It provides a means for
     * dependency injection.
     *
     * @param Engine $engine the engine to use.
     *
     * @return $this the current object, for fluent interface.
     */
    public function setEngine(Engine $engine)
    {
        $this->engine = $engine;
        return $this;
    }

    /**
     * Sets per-command additional arguments
     *
     * @param array $options Additional per-command options for GPG command.
     *                       Note: This will unset options set previously.
     *                       Key of the array is a command (e.g.
     *                       gen-key, import, sign, encrypt, list-keys).
     *                       Value is a string containing command line arguments to be
     *                       added to the related command. For example:
     *                       ['sign' => '--emit-version'].
     *
     * @return $this the current object, for fluent interface.
     */
    public function setEngineOptions(array $options)
    {
        $this->engine->setOptions($options);
        return $this;
    }

    /**
     * Returns version of the engine (GnuPG) used for operation.
     *
     * @return string GnuPG version.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function getVersion(): string
    {
        return $this->engine->getVersion();
    }

    /**
     * Signs data
     *
     * Data may be signed using any one of the three available signing modes:
     * - {@link self::SIGN_MODE_NORMAL}
     * - {@link self::SIGN_MODE_CLEAR}
     * - {@link self::SIGN_MODE_DETACHED}
     *
     * @param string  $data     the data to be signed.
     * @param int     $mode     optional. The data signing mode to use. Should
     *                          be one of {@link self::SIGN_MODE_NORMAL},
     *                          {@link self::SIGN_MODE_CLEAR} or
     *                          {@link self::SIGN_MODE_DETACHED}. If not
     *                          specified, defaults to
     *                          <kbd>self::SIGN_MODE_NORMAL</kbd>.
     * @param bool    $armor    optional. If true, ASCII armored data is
     *                          returned; otherwise, binary data is returned.
     *                          Defaults to true. This has no effect if the
     *                          mode <kbd>self::SIGN_MODE_CLEAR</kbd> is
     *                          used.
     * @param bool    $textmode optional. If true, line-breaks in signed data
     *                          are normalized. Use this option when signing
     *                          e-mail, or for greater compatibility between
     *                          systems with different line-break formats.
     *                          Defaults to false. This has no effect if the
     *                          mode <kbd>self::SIGN_MODE_CLEAR</kbd> is
     *                          used as clear-signing always uses textmode.
     *
     * @return string the signed data, or the signature data if a detached
     *                signature is requested.
     *
     * @throws Exceptions\KeyNotFoundException if no signing key is specified.
     *         See {@link self::addSignKey()}.
     *
     * @throws Exceptions\BadPassphraseException if a specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function sign($data, $mode = self::SIGN_MODE_NORMAL, $armor = self::ARMOR_ASCII, $textmode = self::TEXT_RAW): string
    {
        return $this->_sign($data, false, null, $mode, $armor, $textmode);
    }

    /**
     * Signs a file
     *
     * The file may be signed using any one of the three available signing
     * modes:
     * - {@link self::SIGN_MODE_NORMAL}
     * - {@link self::SIGN_MODE_CLEAR}
     * - {@link self::SIGN_MODE_DETACHED}
     *
     * @param string  $filename   the name of the file containing the data to
     *                            be signed.
     * @param string  $signedFile optional. The name of the file in which the
     *                            signed data should be stored. If null or
     *                            unspecified, the signed data is returned as a
     *                            string.
     * @param int     $mode       optional. The data signing mode to use. Should
     *                            be one of {@link self::SIGN_MODE_NORMAL},
     *                            {@link self::SIGN_MODE_CLEAR} or
     *                            {@link self::SIGN_MODE_DETACHED}. If not
     *                            specified, defaults to
     *                            <kbd>self::SIGN_MODE_NORMAL</kbd>.
     * @param bool    $armor      optional. If true, ASCII armored data is
     *                            returned; otherwise, binary data is returned.
     *                            Defaults to true. This has no effect if the
     *                            mode <kbd>self::SIGN_MODE_CLEAR</kbd> is
     *                            used.
     * @param bool    $textmode   optional. If true, line-breaks in signed data
     *                            are normalized. Use this option when signing
     *                            e-mail, or for greater compatibility between
     *                            systems with different line-break formats.
     *                            Defaults to false. This has no effect if the
     *                            mode <kbd>self::SIGN_MODE_CLEAR</kbd> is
     *                            used as clear-signing always uses textmode.
     *
     * @return string|null if the <kbd>$signedFile</kbd> parameter is null, a
     *                     string containing the signed data (or the signature
     *                     data if a detached signature is requested) is returned.
     *
     * @throws Exceptions\KeyNotFoundException if no signing key is specified.
     *         See {@link self::addSignKey()}.
     *
     * @throws Exceptions\BadPassphraseException if a specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function signFile(
        $filename,
        $signedFile = null,
        $mode = self::SIGN_MODE_NORMAL,
        $armor = self::ARMOR_ASCII,
        $textmode = self::TEXT_RAW
    ): ?string {
        return $this->_sign($filename, true, $signedFile, $mode, $armor, $textmode);
    }

    /**
     * Verifies signed data
     *
     * The {@link self::decrypt()} method may be used to get the original
     * message if the signed data is not clearsigned and does not use a
     * detached signature.
     *
     * @param string $signedData the signed data to be verified.
     * @param string $signature  optional. If verifying data signed using a
     *                           detached signature, this must be the detached
     *                           signature data. The data that was signed is
     *                           specified in <kbd>$signedData</kbd>.
     *
     * @return array<Signature> An array of {@link \Crypt\GPG\Signature} objects for the
     *               signed data. For each signature that is valid, the
     *               {@link \Crypt\GPG\Signature::isValid()} will return true.
     *
     * @throws Exceptions\KeyNotFoundException if the public key needed for
     *         signature verification is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if the provided data is not signed
     *         data.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function verify($signedData, $signature = ''): array
    {
        return $this->_verify($signedData, false, $signature);
    }

    /**
     * Verifies a signed file
     *
     * The {@link self::decryptFile()} method may be used to get the
     * original message if the signed data is not clearsigned and does not use
     * a detached signature.
     *
     * @param string $filename  the signed file to be verified.
     * @param string $signature optional. If verifying a file signed using a
     *                          detached signature, this must be the detached
     *                          signature data. The file that was signed is
     *                          specified in <kbd>$filename</kbd>.
     *
     * @return array<Signature> An array of {@link \Crypt\GPG\Signature} objects for the
     *               signed data. For each signature that is valid, the
     *               {@link \Crypt\GPG\Signature::isValid()} will return true.
     *
     * @throws Exceptions\KeyNotFoundException if the public key needed for
     *         signature verification is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if the provided data is not signed
     *         data.
     *
     * @throws Exceptions\FileException if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function verifyFile($filename, $signature = ''): array
    {
        return $this->_verify($filename, true, $signature);
    }

    /**
     * Adds a key to use for decryption
     *
     * @param mixed  $key        the key to use. This may be a key identifier,
     *                           user id, fingerprint, {@link \Crypt\GPG\Key} or
     *                           {@link \Crypt\GPG\SubKey}. The key must be able
     *                           to encrypt.
     * @param string $passphrase optional. The passphrase of the key required
     *                           for decryption.
     *
     * @return $this the current object, for fluent interface.
     *
     * @see self::decrypt()
     * @see self::decryptFile()
     * @see self::clearDecryptKeys()
     * @see self::_addKey()
     *
     * @sensitive $passphrase
     */
    public function addDecryptKey($key, $passphrase = null)
    {
        $this->_addKey($this->decryptKeys, false, false, $key, $passphrase);
        return $this;
    }

    /**
     * Adds a key to use for encryption
     *
     * @param mixed $key the key to use. This may be a key identifier, user id
     *                   user id, fingerprint, {@link \Crypt\GPG\Key} or
     *                   {@link \Crypt\GPG\SubKey}. The key must be able to
     *                   encrypt.
     *
     * @return $this the current object, for fluent interface.
     *
     * @see self::encrypt()
     * @see self::encryptFile()
     * @see self::clearEncryptKeys()
     * @see self::_addKey()
     */
    public function addEncryptKey($key)
    {
        $this->_addKey($this->encryptKeys, true, false, $key);
        return $this;
    }

    /**
     * Adds a key to use for signing
     *
     * @param mixed  $key        the key to use. This may be a key identifier,
     *                           user id, fingerprint, {@link \Crypt\GPG\Key} or
     *                           {@link \Crypt\GPG\SubKey}. The key must be able
     *                           to sign.
     * @param string $passphrase optional. The passphrase of the key required
     *                           for signing.
     *
     * @return $this the current object, for fluent interface.
     *
     * @see self::sign()
     * @see self::signFile()
     * @see self::clearSignKeys()
     * @see self::_addKey()
     *
     * @sensitive $passphrase
     */
    public function addSignKey($key, $passphrase = null)
    {
        $this->_addKey($this->signKeys, false, true, $key, $passphrase);
        return $this;
    }

    /**
     * Register a private key passphrase for import/export.
     *
     * @param string|Key $key        The key to use. This must be a key identifier,
     *                               or fingerprint or a Key object.
     * @param string     $passphrase The passphrase of the key.
     *
     * @return $this the current object, for fluent interface.
     *
     * @see self::clearPassphrases()
     * @see self::importKey()
     * @see self::exportKey()
     *
     * @sensitive $passphrase
     */
    public function addPassphrase($key, $passphrase)
    {
        $this->passphrases[$key] = $passphrase;
        return $this;
    }

    /**
     * Clears all decryption keys
     *
     * @return $this the current object, for fluent interface.
     *
     * @see self::decrypt()
     * @see self::addDecryptKey()
     */
    public function clearDecryptKeys()
    {
        $this->decryptKeys = [];
        return $this;
    }

    /**
     * Clears all encryption keys
     *
     * @return $this the current object, for fluent interface.
     *
     * @see self::encrypt()
     * @see self::addEncryptKey()
     */
    public function clearEncryptKeys()
    {
        $this->encryptKeys = [];
        return $this;
    }

    /**
     * Clears all signing keys
     *
     * @return $this The current object, for fluent interface.
     *
     * @see self::sign()
     * @see self::addSignKey()
     */
    public function clearSignKeys()
    {
        $this->signKeys = [];
        return $this;
    }

    /**
     * Clears all private key passphrases
     *
     * @return $this The current object, for fluent interface.
     *
     * @see self::importKey()
     * @see self::exportKey()
     * @see self::addPassphrase()
     */
    public function clearPassphrases()
    {
        $this->passphrases = [];
        return $this;
    }

    /**
     * Exports an owner trust information.
     *
     * Note that trust level values here are shifted by +1 in relation
     * to the levels in the key editor's trust command.
     *
     * @return array<string, int> Key fingerprint to trust level map
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    public function getOwnerTrust(): array
    {
        $output = '';
        $this->engine->reset();
        $this->engine->setOutput($output);
        $this->engine->setOperation('--export-ownertrust', []);
        $this->engine->run();

        $result = [];
        foreach (explode(PHP_EOL, $output) as $line) {
            if (preg_match('/^([0-9A-F]{16,}):(\d+):/', $line, $matches)) {
                $result[$matches[1]] = (int) $matches[2];
            }
        }

        return $result;
    }

    /**
     * Tell if there are encryption keys registered
     */
    public function hasEncryptKeys(): bool
    {
        return count($this->encryptKeys) > 0;
    }

    /**
     * Tell if there are signing keys registered
     */
    public function hasSignKeys(): bool
    {
        return count($this->signKeys) > 0;
    }

    /**
     * Get list of GnuPG warnings collected on last operation.
     *
     * @return array List of warning messages
     */
    public function getWarnings(): array
    {
        return $this->engine->getProcessData('Warnings');
    }

    /**
     * Adds a key to one of the internal key arrays
     *
     * This handles resolving full key objects from the provided
     * <kbd>$key</kbd> value.
     *
     * @param array             &$array     The array to which the key should be added
     * @param bool              $encrypt    Whether or not the key must be able to
     *                                      encrypt
     * @param bool              $sign       Whether or not the key must be able to sign
     * @param string|Key|SubKey $key        The key to add. This may be a key identifier,
     *                                      user id, fingerprint, {@link \Crypt\GPG\Key} or
     *                                      {@link \Crypt\GPG\SubKey}
     * @param string            $passphrase Optional passphrase associated with the key
     *
     * @sensitive $passphrase
     */
    protected function _addKey(array &$array, $encrypt, $sign, $key, $passphrase = null): void
    {
        $subKeys = [];

        if (is_scalar($key)) {
            $keys = $this->getKeys($key);
            if (count($keys) == 0) {
                throw new Exceptions\KeyNotFoundException(
                    'Key not found: ' . $key,
                    self::ERROR_KEY_NOT_FOUND,
                    $key
                );
            }
            $key = $keys[0];
        }

        if ($key instanceof Key) {
            if ($encrypt && !$key->canEncrypt()) {
                throw new \InvalidArgumentException('Key "' . $key . '" cannot encrypt.');
            }

            if ($sign && !$key->canSign()) {
                throw new \InvalidArgumentException('Key "' . $key . '" cannot sign.');
            }

            foreach ($key->getSubKeys() as $subKey) {
                $canEncrypt = $subKey->canEncrypt();
                $canSign    = $subKey->canSign();
                if (($encrypt && $sign && $canEncrypt && $canSign)
                    || ($encrypt && !$sign && $canEncrypt)
                    || (!$encrypt && $sign && $canSign)
                    || (!$encrypt && !$sign)
                ) {
                    // We add all subkeys that meet the requirements because we
                    // were not told which subkey is required.
                    $subKeys[] = $subKey;
                }
            }
        } elseif ($key instanceof SubKey) {
            $subKeys[] = $key;
        }

        if (count($subKeys) === 0) {
            throw new \InvalidArgumentException('Key "' . $key . '" is not in a recognized format.');
        }

        foreach ($subKeys as $subKey) {
            if ($encrypt && !$subKey->canEncrypt()) {
                throw new \InvalidArgumentException('Key "' . $key . '" cannot encrypt.');
            }

            if ($sign && !$subKey->canSign()) {
                throw new \InvalidArgumentException('Key "' . $key . '" cannot sign.');
            }

            $array[$subKey->getId()] = [
                'fingerprint' => $subKey->getFingerprint(),
                'passphrase'  => $passphrase,
            ];
        }
    }

    /**
     * Imports a public or private key into the keyring
     *
     * @param string $key    The key to be imported.
     * @param bool   $isFile Whether or not the input is a filename.
     *
     * @return array an associative array containing the following elements:
     *               - <kbd>fingerprint</kbd>       - the fingerprint of the
     *                                                imported key,
     *               - <kbd>public_imported</kbd>   - the number of public
     *                                                keys imported,
     *               - <kbd>public_unchanged</kbd>  - the number of unchanged
     *                                                public keys,
     *               - <kbd>private_imported</kbd>  - the number of private
     *                                                keys imported,
     *               - <kbd>private_unchanged</kbd> - the number of unchanged
     *                                                private keys.
     *
     * @throws Exceptions\NoDataException if the key data is missing or if the
     *         data is is not valid key data.
     *
     * @throws Exceptions\FileException if the key file is not readable.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addPassphrase()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _importKey($key, $isFile)
    {
        $result    = [];
        $arguments = [];
        $input     = $this->_prepareInput($key, $isFile, false);

        if (empty($this->passphrases)) {
            $arguments[] = '--batch';
        }

        $this->engine->reset();
        $this->engine->setPins($this->passphrases);
        $this->engine->setOperation('--import', $arguments);
        $this->engine->setInput($input);
        $this->engine->run();

        return $this->engine->getProcessData('Import');
    }

    /**
     * Exports a private or public key from the keyring
     *
     * If more than one key fingerprint is available for the specified
     * <kbd>$keyId</kbd> (for example, if you use a non-unique uid) only the
     * first key is exported.
     *
     * @param Key|string $keyId   Either the {@link Crypt\GPG\Key} object or full uid of the public key,
     *                            the email part of the uid of the public key or the key id of
     *                            the public key. For example "Test User (example) <test@example.com>",
     *                            "test@example.com" or a hexadecimal string.
     * @param bool       $armor   Optional. If true, ASCII armored data is returned;
     *                            otherwise, binary data is returned. Defaults to
     *                            true.
     * @param bool       $private Return private instead of public key
     *
     * @return string the key data.
     *
     * @throws Exceptions\KeyNotFoundException if a key with the given
     *         <kbd>$keyId</kbd> is not found.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addPassphrase()}.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _exportKey($keyId, $armor = true, $private = false)
    {
        $fingerprint = $this->toFingerprint($keyId);

        $keyData   = '';
        $operation = $private ? '--export-secret-keys' : '--export';
        $operation .= ' -- ' . escapeshellarg($fingerprint);
        $arguments = $armor ? ['--armor'] : [];

        $this->engine->reset();
        $this->engine->setPins($this->passphrases);
        $this->engine->setOutput($keyData);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        return $keyData;
    }

    /**
     * Encrypts data
     *
     * @param string      $data       The data to encrypt.
     * @param bool        $isFile     Whether or not the data is a filename.
     * @param string|null $outputFile The filename of the file in which to store
     *                                the encrypted data. If null, the encrypted
     *                                data is returned as a string.
     * @param bool        $armor      If true, ASCII armored data is returned;
     *                                otherwise, binary data is returned.
     *
     * @return string|null If the <kbd>$outputFile</kbd> parameter is null,
     *                     a string containing the encrypted data is returned.
     *
     * @throws Exceptions\KeyNotFoundException if no encryption key is specified.
     *         See {@link self::addEncryptKey()}.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _encrypt($data, $isFile, $outputFile, $armor)
    {
        if (!$this->hasEncryptKeys()) {
            throw new Exceptions\KeyNotFoundException('No encryption keys specified.');
        }

        $input     = $this->_prepareInput($data, $isFile);
        $output    = $this->_prepareOutput($outputFile, $input);
        $arguments = $armor ? ['--armor'] : [];

        foreach ($this->encryptKeys as $key) {
            $arguments[] = '--recipient ' . escapeshellarg($key['fingerprint']);
        }

        $this->engine->reset();
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation('--encrypt', $arguments);
        $this->engine->run();

        return $outputFile === null ? $output : null;
    }

    /**
     * Decrypts data
     *
     * @param string      $data       The data to be decrypted.
     * @param bool        $isFile     Whether or not the data is a filename.
     * @param string|null $outputFile The name of the file to which the decrypted
     *                                data should be written. If null, the decrypted
     *                                data is returned as a string.
     *
     * @return string|null if the <kbd>$outputFile</kbd> parameter is null, a
     *                     string containing the decrypted data is returned.
     *
     * @throws Exceptions\KeyNotFoundException if the private key needed to
     *         decrypt the data is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if specified data does not contain
     *         GPG encrypted data.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addDecryptKey()}.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _decrypt($data, $isFile, $outputFile)
    {
        $input  = $this->_prepareInput($data, $isFile, false);
        $output = $this->_prepareOutput($outputFile, $input);

        $this->engine->reset();
        $this->engine->setPins($this->decryptKeys);
        $this->engine->setOperation('--decrypt --skip-verify');
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->run();

        return $outputFile === null ? $output : null;
    }

    /**
     * Signs data
     *
     * @param string      $data       The data to be signed.
     * @param bool        $isFile     Whether or not the data is a filename.
     * @param string|null $outputFile The name of the file in which the signed data
     *                                should be stored. If null, the signed data is
     *                                returned as a string.
     * @param int         $mode       The data signing mode to use. Should be one of
     *                                {@link self::SIGN_MODE_NORMAL},
     *                                {@link self::SIGN_MODE_CLEAR} or
     *                                {@link self::SIGN_MODE_DETACHED}.
     * @param bool        $armor      If true, ASCII armored data is returned;
     *                                otherwise, binary data is returned. This has
     *                                no effect if the mode
     *                                <kbd>self::SIGN_MODE_CLEAR</kbd> is
     *                                used.
     * @param bool        $textmode   If true, line-breaks in signed data be
     *                                normalized. Use this option when signing
     *                                e-mail, or for greater compatibility between
     *                                systems with different line-break formats.
     *                                Defaults to false. This has no effect if the
     *                                mode <kbd>self::SIGN_MODE_CLEAR</kbd> is
     *                                used as clear-signing always uses textmode.
     *
     * @return string|null if the <kbd>$outputFile</kbd> parameter is null, a
     *                     string containing the signed data (or the signature
     *                     data if a detached signature is requested) is returned.
     *
     * @throws Exceptions\KeyNotFoundException if no signing key is specified.
     *         See {@link self::addSignKey()}.
     *
     * @throws Exceptions\BadPassphraseException if a specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _sign($data, $isFile, $outputFile, $mode, $armor, $textmode)
    {
        if (!$this->hasSignKeys()) {
            throw new Exceptions\KeyNotFoundException('No signing keys specified.');
        }

        $input  = $this->_prepareInput($data, $isFile);
        $output = $this->_prepareOutput($outputFile, $input);

        switch ($mode) {
            case self::SIGN_MODE_DETACHED:
                $operation = '--detach-sign';
                break;
            case self::SIGN_MODE_CLEAR:
                $operation = '--clearsign';
                break;
            case self::SIGN_MODE_NORMAL:
            default:
                $operation = '--sign';
                break;
        }

        $arguments = [];

        if ($armor) {
            $arguments[] = '--armor';
        }
        if ($textmode) {
            $arguments[] = '--textmode';
        }

        foreach ($this->signKeys as $key) {
            $arguments[] = '--local-user ' . escapeshellarg($key['fingerprint']);
        }

        $this->engine->reset();
        $this->engine->setPins($this->signKeys);
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        return $outputFile === null ? $output : null;
    }

    /**
     * Encrypts and signs data
     *
     * @param string      $data       The data to be encrypted and signed.
     * @param bool        $isFile     Whether or not the data is a filename.
     * @param string|null $outputFile The name of the file in which the encrypted,
     *                                signed data should be stored. If null, the
     *                                encrypted, signed data is returned as a
     *                                string.
     * @param bool        $armor      If true, ASCII armored data is returned;
     *                                otherwise, binary data is returned.
     *
     * @return string|null if the <kbd>$outputFile</kbd> parameter is null, a
     *                     string containing the encrypted, signed data is returned.
     *
     * @throws Exceptions\KeyNotFoundException if no encryption key is specified
     *         or if no signing key is specified. See
     *         {@link self::addEncryptKey()} and
     *         {@link self::addSignKey()}.
     *
     * @throws Exceptions\BadPassphraseException if a specified passphrase is
     *         incorrect or if a required passphrase is not specified.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _encryptAndSign($data, $isFile, $outputFile, $armor)
    {
        if (!$this->hasSignKeys()) {
            throw new Exceptions\KeyNotFoundException('No signing keys specified.');
        }

        if (!$this->hasEncryptKeys()) {
            throw new Exceptions\KeyNotFoundException('No encryption keys specified.');
        }

        $input     = $this->_prepareInput($data, $isFile);
        $output    = $this->_prepareOutput($outputFile, $input);
        $arguments = $armor ? ['--armor'] : [];

        foreach ($this->signKeys as $key) {
            $arguments[] = '--local-user ' . escapeshellarg($key['fingerprint']);
        }

        foreach ($this->encryptKeys as $key) {
            $arguments[] = '--recipient ' . escapeshellarg($key['fingerprint']);
        }

        $this->engine->reset();
        $this->engine->setPins($this->signKeys);
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation('--encrypt --sign', $arguments);
        $this->engine->run();

        return $outputFile === null ? $output : null;
    }

    /**
     * Verifies data
     *
     * @param string  $data      the signed data to be verified.
     * @param bool    $isFile    whether or not the data is a filename.
     * @param string  $signature if verifying a file signed using a detached
     *                           signature, this must be the detached signature
     *                           data. Otherwise, specify ''.
     *
     * @return array<Signature> An array of {@link \Crypt\GPG\Signature} objects for the
     *                          signed data.
     *
     * @throws Exceptions\KeyNotFoundException if the public key needed for
     *         signature verification is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if the provided data is not signed
     *         data.
     *
     * @throws Exceptions\FileException if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _verify($data, $isFile, $signature)
    {
        if ($signature == '') {
            $operation = '--verify';
            $arguments = [];
        } else {
            // Signed data goes in FD_MESSAGE, detached signature data goes in FD_INPUT.
            $operation = '--verify - "-&' . Engine::FD_MESSAGE . '"';
            $arguments = ['--enable-special-filenames'];
        }

        $input = $this->_prepareInput($data, $isFile, false);

        $this->engine->reset();

        if ($signature == '') {
            // signed or clearsigned data
            $this->engine->setInput($input);
        } else {
            // detached signature
            $this->engine->setInput($signature);
            $this->engine->setMessage($input);
        }

        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        return $this->engine->getProcessData('Signatures');
    }

    /**
     * Decrypts and verifies encrypted, signed data
     *
     * @param string      $data               The encrypted signed data to be decrypted and
     *                                        verified.
     * @param bool        $isFile             Whether or not the data is a filename.
     * @param string|null $outputFile         The name of the file to which the decrypted
     *                                        data should be written. If null, the decrypted
     *                                        data is returned in the results array.
     * @param bool        $ignoreVerifyErrors Enables ignoring of signature verification
     *                                        errors caused by missing public key.
     *                                        When enabled \Crypt\GPG\KeyNotFoundException
     *                                        will not be thrown.
     *
     * @return array two element array. The array has an element 'data'
     *               containing the decrypted data and an element
     *               'signatures' containing an array of
     *               {@link \Crypt\GPG\Signature} objects for the signed data.
     *               If the decrypted data is written to a file, the 'data'
     *               element is null.
     *
     * @throws Exceptions\KeyNotFoundException if the private key needed to
     *         decrypt the data is not in the user's keyring or if the public
     *         key needed for verification is not in the user's keyring.
     *
     * @throws Exceptions\NoDataException if specified data does not contain
     *         GPG signed, encrypted data.
     *
     * @throws Exceptions\BadPassphraseException if a required passphrase is
     *         incorrect or if a required passphrase is not specified. See
     *         {@link self::addDecryptKey()}.
     *
     * @throws Exceptions\FileException if the output file is not writeable or
     *         if the input file is not readable.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _decryptAndVerify($data, $isFile, $outputFile, $ignoreVerifyErrors = false)
    {
        $input  = $this->_prepareInput($data, $isFile, false);
        $output = $this->_prepareOutput($outputFile, $input);

        $this->engine->reset();
        $this->engine->setPins($this->decryptKeys);
        $this->engine->setInput($input);
        $this->engine->setOutput($output);
        $this->engine->setOperation('--decrypt');
        $this->engine->setProcessData('IgnoreVerifyErrors', $ignoreVerifyErrors);
        $this->engine->run();

        return [
            'data'       => $outputFile === null ? $output : null,
            'signatures' => $this->engine->getProcessData('Signatures'),
        ];
    }

    /**
     * Gets the available keys in the keyring
     *
     * Calls GPG with the <kbd>--list-keys</kbd> command and grabs keys. See
     * the first section of <b>doc/DETAILS</b> in the
     * {@link http://www.gnupg.org/download/ GPG package} for a detailed
     * description of how the GPG command output is parsed.
     *
     * @param string $keyId optional. Only keys with that match the specified
     *                      pattern are returned. The pattern may be part of
     *                      a user id, a key id or a key fingerprint. If not
     *                      specified, all keys are returned.
     *
     * @return array<Key> An array of {@link \Crypt\GPG\Key} objects. If no keys
     *                    match the specified <kbd>$keyId</kbd> an empty array is
     *                    returned.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     */
    protected function _getKeys($keyId = '')
    {
        // double '--with-fingerprint' also prints the fingerprint for subkeys.
        $arguments = [
            '--with-colons',
            '--with-fingerprint',
            '--with-fingerprint',
            '--fixed-list-mode',
            '--with-secret',
        ];

        // get public keys
        if ($keyId == '') {
            $operation = '--list-keys';
        } else {
            $operation = '--utf8-strings --list-keys -- ' . escapeshellarg($keyId);
        }

        $output = '';

        $this->engine->reset();
        $this->engine->setOutput($output);
        $this->engine->setOperation($operation, $arguments);
        $this->engine->run();

        return self::_parseListOutput($output);
    }

    /**
     * Parse output from a keys/signatures listing command
     */
    protected static function _parseListOutput($output)
    {
        $keys   = [];
        $key    = null; // current key
        $subKey = null; // current sub-key
        $userId = null; // current user-id

        foreach (explode(PHP_EOL, $output) as $line) {
            [$type] = explode(':', $line, 2);

            if ($type == 'pub') {
                // new primary key means last key should be added to the array
                if ($key) {
                    $keys[] = $key;
                    $userId = null;
                }

                $key = new Key();
                $subKey = SubKey::parse($line);
                $key->addSubKey($subKey);
            } elseif ($type == 'sub') {
                $subKey = SubKey::parse($line);
                $key->addSubKey($subKey);
                $userId = null;
            } elseif ($type == 'fpr') {
                $lineExp = explode(':', $line);
                $subKey->setFingerprint($lineExp[9]);
            } elseif ($type == 'uid') {
                $userId = UserId::parse($line);
                $key->addUserId($userId);
            } elseif ($type == 'sig' && $userId) {
                // Note: sig: lines are available when using --with-sig-list or --with-sig-check
                $userId->addSignature(Signature::parse($line));
            }
        }

        // add last key
        if ($key) {
            $keys[] = $key;
        }

        return $keys;
    }

    /**
     * Prepares command input
     *
     * @param string $data       The input data
     * @param bool   $isFile     Whether or not the input is a filename
     * @param bool   $allowEmpty Whether to check if the input is not empty
     *
     * @throws Exceptions\NoDataException if the key data is missing.
     * @throws Exceptions\FileException if the file is not readable.
     *
     * @return string|resource The command input
     */
    protected function _prepareInput($data, $isFile = false, $allowEmpty = true)
    {
        if ($isFile) {
            $input = @fopen($data, 'rb');
            if ($input === false) {
                throw new Exceptions\FileException(
                    'Could not open input file "' . $data . '"',
                    0,
                    $data
                );
            }
        } else {
            $input = strval($data);
            if (!$allowEmpty && $input === '') {
                throw new Exceptions\NoDataException(
                    'No valid input data found.',
                    self::ERROR_NO_DATA
                );
            }
        }

        return $input;
    }

    /**
     * Prepares command output
     *
     * @param string|null   $outputFile The name of the file in which the output
     *                                  data should be stored. If null, the output
     *                                  data is returned as a string.
     * @param resource|null $input      The input resource, in case it would need
     *                                  to be released (closed) on exception.
     *
     * @throws Exceptions\FileException if the file is not writeable.
     *
     * @return string|resource The command output
     */
    protected function _prepareOutput($outputFile, $input = null)
    {
        if ($outputFile === null) {
            $output = '';
        } else {
            $output = @fopen($outputFile, 'wb');
            if ($output === false) {
                if (is_resource($input)) {
                    fclose($input);
                }
                throw new Exceptions\FileException(
                    'Could not open output file "' . $outputFile . '"',
                    0,
                    $outputFile
                );
            }
        }

        return $output;
    }

    /**
     * Find fingerprint for the key id input
     *
     * @param mixed $input Input
     */
    protected function toFingerprint($input): string
    {
        if (is_string($input) && strlen($input)) {
            if (preg_match('/^[0-9A-F]{40}$/', $input)) {
                return $input;
            }

            if ($fingerprint = $this->getFingerprint($input)) {
                return $fingerprint;
            }
        } elseif ($input instanceof Key) {
            if ($pkey = $input->getPrimaryKey()) {
                if ($fingerprint = $pkey->getFingerprint()) {
                    return $fingerprint;
                }
            }
        }

        throw new Exceptions\KeyNotFoundException('Key not found: ' . $input, self::ERROR_KEY_NOT_FOUND, $input);
    }
}
