<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG\Exceptions;

/**
 * An exception thrown when an attempt is made to generate a key and the
 * key parameters set on the key generator are invalid
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
 * @copyright 2011 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class InvalidKeyParamsException extends Exception
{
    /**
     * The key algorithm
     *
     * @var int
     */
    private $_algorithm = 0;

    /**
     * The key size
     *
     * @var int
     */
    private $_size = 0;

    /**
     * The key usage
     *
     * @var int
     */
    private $_usage = 0;

    /**
     * Creates a new InvalidKeyParamsException
     *
     * @param string $message   An error message.
     * @param int    $code      A user defined error code.
     * @param int    $algorithm The key algorithm.
     * @param int    $size      The key size.
     * @param int    $usage     The key usage.
     */
    public function __construct($message, $code = 0, $algorithm = 0, $size = 0, $usage = 0)
    {
        parent::__construct($message, $code);

        $this->_algorithm = (int) $algorithm;
        $this->_size      = (int) $size;
        $this->_usage     = (int) $usage;
    }

    /**
     * Gets the key algorithm
     *
     * @return int The key algorithm.
     */
    public function getAlgorithm()
    {
        return $this->_algorithm;
    }

    /**
     * Gets the key size
     *
     * @return int The key size.
     */
    public function getSize()
    {
        return $this->_size;
    }

    /**
     * Gets the key usage
     *
     * @return int The key usage.
     */
    public function getUsage()
    {
        return $this->_usage;
    }
}
