<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Exceptions;

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
     * Creates a new OpenSubprocessException
     *
     * @param string $message   An error message.
     * @param int    $code      A user defined error code.
     * @param string $operation The operation.
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
     * @see self::$_operation
     */
    public function getOperation()
    {
        return $this->_operation;
    }
}
