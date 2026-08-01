<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Exceptions;

/**
 * An exception thrown when a file is used in ways it cannot be used
 *
 * For example, if an output file is specified and the file is not writeable, or
 * if an input file is specified and the file is not readable, this exception
 * is thrown.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2007-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class FileException extends Exception
{
    /**
     * The name of the file that caused this exception
     *
     * @var string
     */
    private $_filename = '';

    /**
     * Creates a new FileException
     *
     * @param string $message  An error message.
     * @param int    $code     A user defined error code.
     * @param string $filename The name of the file that caused this exception.
     */
    public function __construct($message, $code = 0, $filename = '')
    {
        $this->_filename = $filename;
        parent::__construct($message, $code);
    }

    /**
     * Returns the filename of the file that caused this exception
     *
     * @return string the filename of the file that caused this exception.
     *
     * @see self::$_filename
     */
    public function getFilename()
    {
        return $this->_filename;
    }
}
