<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Various exception handling classes for Crypt_GPG
 *
 * Crypt_GPG provides an object oriented interface to GNU Privacy
 * Guard (GPG). It requires the GPG executable to be on the system.
 *
 * This file contains various exception classes used by the Crypt_GPG package.
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
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * PEAR Exception handler and base class
 */
require_once 'PEAR/Exception.php';

// {{{ class Crypt_GPG_Exception

/**
 * An exception class thrown by the Crypt_GPG class
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_Exception extends PEAR_Exception
{
}

// }}}
// {{{ class Crypt_GPG_FileException

/**
 * This exception is thrown when the Crypt_GPG class tries to use a file in
 * ways it cannot be used
 *
 * For example, if an output file is specified and the file is not writeable or
 * if an input file is specified and the file is not readable.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2007 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_FileException extends Crypt_GPG_Exception
{
    // {{{ private class properties

    /**
     * The name of the file that caused this exception
     *
     * @var string
     */
    private $_filename = '';

    // }}}
    // {{{ __construct()

    /**
     * Creates a new Crypt_GPG_FileException
     *
     * @param string $message  an error message.
     * @param int    $code     a user defined error code.
     * @param string $filename the name of the file that caused this exception.
     */
    public function __construct($message, $code = 0, $filename = '')
    {
        $this->_filename = $filename;
        parent::__construct($message, $code);
    }

    // }}}
    // {{{ getFilename()

    /**
     * Returns the filename of the file that caused this exception
     *
     * @return string the filename of the file that caused this exception.
     *
     * @see Crypt_GPG_FileException::$_filename
     */
    public function getFilename()
    {
        return $this->_filename;
    }

    // }}}
}

// }}}
// {{{ class Crypt_GPG_OpenSubprocessException

/**
 * An exception class thrown by the Crypt_GPG::_openSubprocess() method
 *
 * This exception is thrown when the Crypt_GPG class tries to open a new
 * subprocess and fails.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_OpenSubprocessException extends Crypt_GPG_Exception
{
    // {{{ private class properties

    /**
     * The command used to try to open the subprocess
     *
     * @var string
     */
    private $_command = '';

    // }}}
    // {{{ __construct()

    /**
     * Creates a new Crypt_GPG_OpenSubprocessException
     *
     * @param string $message an error message.
     * @param int    $code    a user defined error code.
     * @param string $command the command that was called to open the
     *                        new subprocess.
     *
     * @see Crypt_GPG::_openSubprocess()
     */
    public function __construct($message, $code = 0, $command = '')
    {
        $this->_command = $command;
        parent::__construct($message, $code);
    }

    // }}}
    // {{{ getCommand()

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

    // }}}
}

// }}}
// {{{ class Crypt_GPG_KeyNotFoundException

/**
 * This exception is thrown when the Crypt_GPG class fails to find the key for
 * various opetations
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_KeyNotFoundException extends Crypt_GPG_Exception
{
    // {{{ private class properties

    /**
     * The key identifier that was searched for
     *
     * @var string
     */
    private $_key_id = '';

    // }}}
    // {{{ __construct()

    /**
     * Creates a new Crypt_GPG_KeyNotFoundException
     *
     * @param string $message an error message.
     * @param int    $code    a user defined error code.
     * @param string $key_id  the key identifier of the secret key that was
     *                        attempted to delete.
     *
     * @see Crypt_GPG::_deleteSecretKey()
     */
    public function __construct($message, $code = 0, $key_id= '')
    {
        $this->_key_id = $key_id;
        parent::__construct($message, $code);
    }

    // }}}
    // {{{ getKeyId()

    /**
     * Returns the contents of the internal _key_id property
     *
     * @return string the key identifier of the key that was not found.
     *
     * @see Crypt_GPG_OpenSubprocessException::$_key_id
     */
    public function getKeyId()
    {
        return $this->_key_id;
    }

    // }}}
}

// }}}
// {{{ class Crypt_GPG_NoDataException

/**
 * An exception class thrown when the GPG process cannot find data for
 * various operations
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2006 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_NoDataException extends Crypt_GPG_Exception
{
}

// }}}
// {{{ class Crypt_GPG_BadPassphraseException

/**
 * An exception class thrown when the GPG passphrase is bad or missing
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2006 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_BadPassphraseException extends Crypt_GPG_Exception
{
}

// }}}
// {{{ class Crypt_GPG_DuplicateKeyImportException

/**
 * An exception thrown when a key that is already in the keyring is imported
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2006 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_DuplicateKeyImportException extends Crypt_GPG_Exception
{
}

// }}}
// {{{ class Crypt_GPG_UnsignedKeyException

/**
 * An exception thrown when a key that is not signed is use for encryption
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2006 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_UnsignedKeyException extends Crypt_GPG_Exception
{
}

// }}}
// {{{ class Crypt_GPG_MissingSelfSignatureException

/**
 * An exception thrown when a key that is not self signed is used for
 * encryption
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2006 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_MissingSelfSignatureException extends Crypt_GPG_Exception
{
}

// }}}

?>
