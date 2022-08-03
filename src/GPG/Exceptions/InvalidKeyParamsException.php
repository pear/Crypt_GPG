<?php

namespace Crypt\GPG\Exceptions;

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * An exception thrown when an attempt is made to generate a key and the
 * key parameters set on the key generator are invalid
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
     * @var integer
     */
    private $_algorithm = 0;

    /**
     * The key size
     *
     * @var integer
     */
    private $_size = 0;

    /**
     * The key usage
     *
     * @var integer
     */
    private $_usage = 0;

    /**
     * Creates a new Crypt_GPG_InvalidKeyParamsException
     *
     * @param string  $message   an error message.
     * @param integer $code      a user defined error code.
     * @param string  $algorithm the key algorithm.
     * @param string  $size      the key size.
     * @param string  $usage     the key usage.
     */
    public function __construct(
        $message,
        $code = 0,
        $algorithm = 0,
        $size = 0,
        $usage = 0
    ) {
        parent::__construct($message, $code);

        $this->_algorithm = $algorithm;
        $this->_size      = $size;
        $this->_usage     = $usage;
    }

    /**
     * Gets the key algorithm
     *
     * @return integer the key algorithm.
     */
    public function getAlgorithm()
    {
        return $this->_algorithm;
    }

    /**
     * Gets the key size
     *
     * @return integer the key size.
     */
    public function getSize()
    {
        return $this->_size;
    }

    /**
     * Gets the key usage
     *
     * @return integer the key usage.
     */
    public function getUsage()
    {
        return $this->_usage;
    }
}
