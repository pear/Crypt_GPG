<?php

namespace Crypt\GPG\Exceptions;

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * An exception thrown when an invalid GPG operation is attempted
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class InvalidOperationException extends Exception
{
    /**
     * The attempted operation
     *
     * @var string
     */
    private $_operation = '';

    /**
     * Creates a new Crypt_GPG_OpenSubprocessException
     *
     * @param string  $message   an error message.
     * @param integer $code      a user defined error code.
     * @param string  $operation the operation.
     */
    public function __construct($message, $code = 0, $operation = '')
    {
        $this->_operation = $operation;
        parent::__construct($message, $code);
    }

    /**
     * Returns the contents of the internal _operation property
     *
     * @return string the attempted operation.
     *
     * @see Crypt_GPG_InvalidOperationException::$_operation
     */
    public function getOperation()
    {
        return $this->_operation;
    }
}
