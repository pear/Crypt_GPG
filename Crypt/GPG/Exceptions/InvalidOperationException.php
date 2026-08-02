<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Exceptions;

/**
 * An exception thrown when an invalid GPG operation is attempted
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
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/>
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
