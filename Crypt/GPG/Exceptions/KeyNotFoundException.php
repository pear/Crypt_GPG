<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Exceptions;

/**
 * An exception thrown when Crypt_GPG fails to find the key for various
 * operations
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class KeyNotFoundException extends Exception
{
    /**
     * The key identifier that was searched for
     *
     * @var string
     */
    private $_keyId = '';

    /**
     * Creates a new KeyNotFoundException
     *
     * @param string $message An error message.
     * @param int    $code    A user defined error code.
     * @param string $keyId   The key identifier of the key.
     */
    public function __construct($message, $code = 0, $keyId = '')
    {
        $this->_keyId = (string) $keyId;
        parent::__construct($message, $code);
    }

    /**
     * Gets the key identifier of the key that was not found
     *
     * @return string the key identifier of the key that was not found.
     */
    public function getKeyId(): string
    {
        return $this->_keyId;
    }
}
