<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Exceptions;

/**
 * An exception thrown when the GPG subprocess cannot be opened
 *
 * This exception is thrown when the {@link \Crypt\GPG\Engine} tries to open a
 * new subprocess and fails.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
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
     * Creates a new OpenSubprocessException
     *
     * @param string $message An error message.
     * @param int    $code    A user defined error code.
     * @param string $command The command that was called to open the
     *                        new subprocess.
     *
     * @see \Crypt\GPG\Engine::_openSubprocess()
     */
    public function __construct($message, $code = 0, $command = '')
    {
        $this->_command = (string) $command;
        parent::__construct($message, $code);
    }

    /**
     * Returns the contents of the internal _command property
     *
     * @return string the command used to open the subprocess.
     */
    public function getCommand(): string
    {
        return $this->_command;
    }
}
