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
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
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
        $this->_operation = (string) $operation;
        parent::__construct($message, $code);
    }

    /**
     * Returns the attempted operation
     *
     * @return string the attempted operation
     */
    public function getOperation(): string
    {
        return $this->_operation;
    }
}
