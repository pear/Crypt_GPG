<?php

namespace Crypt\GPG\Exceptions;

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * An exception thrown when Crypt_GPG fails to find the key for various
 * operations
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
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
     * Creates a new Crypt_GPG_KeyNotFoundException
     *
     * @param string  $message an error message.
     * @param integer $code    a user defined error code.
     * @param string  $keyId   the key identifier of the key.
     */
    public function __construct($message, $code = 0, $keyId= '')
    {
        $this->_keyId = $keyId;
        parent::__construct($message, $code);
    }

    /**
     * Gets the key identifier of the key that was not found
     *
     * @return string the key identifier of the key that was not found.
     */
    public function getKeyId()
    {
        return $this->_keyId;
    }
}
