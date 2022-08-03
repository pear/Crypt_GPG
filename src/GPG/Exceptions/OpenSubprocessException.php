<?php

namespace Crypt\GPG\Exceptions;

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * An exception thrown when the GPG subprocess cannot be opened
 *
 * This exception is thrown when the {@link Crypt_GPG_Engine} tries to open a
 * new subprocess and fails.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class OpenSubprocessException extends Exception
{
    /**
     * The command used to try to open the subprocess
     *
     * @var string
     */
    private $_command = '';

    /**
     * Creates a new Crypt_GPG_OpenSubprocessException
     *
     * @param string  $message an error message.
     * @param integer $code    a user defined error code.
     * @param string  $command the command that was called to open the
     *                         new subprocess.
     *
     * @see Crypt_GPG::_openSubprocess()
     */
    public function __construct($message, $code = 0, $command = '')
    {
        $this->_command = $command;
        parent::__construct($message, $code);
    }

    /**
     * Returns the contents of the internal _command property
     *
     * @return string the command used to open the subprocess.
     *
     * @see Crypt_GPG_OpenSubprocessException::$_command
     */
    public function getCommand()
    {
        return $this->_command;
    }
}
