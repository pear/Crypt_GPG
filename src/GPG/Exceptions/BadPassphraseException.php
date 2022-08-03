<?php

namespace Crypt\GPG\Exceptions;

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * An exception thrown when a required passphrase is incorrect or missing
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2006-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class BadPassphraseException extends Exception
{
    /**
     * Keys for which the passhprase is missing
     *
     * This contains primary user ids indexed by sub-key id.
     *
     * @var array
     */
    private $_missingPassphrases = array();

    /**
     * Keys for which the passhprase is incorrect
     *
     * This contains primary user ids indexed by sub-key id.
     *
     * @var array
     */
    private $_badPassphrases = array();

    /**
     * Creates a new Crypt_GPG_BadPassphraseException
     *
     * @param string  $message            an error message.
     * @param integer $code               a user defined error code.
     * @param array   $badPassphrases     an array containing user ids of keys
     *                                    for which the passphrase is incorrect.
     * @param array   $missingPassphrases an array containing user ids of keys
     *                                    for which the passphrase is missing.
     */
    public function __construct($message, $code = 0,
        array $badPassphrases = array(), array $missingPassphrases = array()
    ) {
        $this->_badPassphrases     = (array) $badPassphrases;
        $this->_missingPassphrases = (array) $missingPassphrases;

        parent::__construct($message, $code);
    }

    /**
     * Gets keys for which the passhprase is incorrect
     *
     * @return array an array of keys for which the passphrase is incorrect.
     *               The array contains primary user ids indexed by the sub-key
     *               id.
     */
    public function getBadPassphrases()
    {
        return $this->_badPassphrases;
    }

    /**
     * Gets keys for which the passhprase is missing 
     *
     * @return array an array of keys for which the passphrase is missing.
     *               The array contains primary user ids indexed by the sub-key
     *               id.
     */
    public function getMissingPassphrases()
    {
        return $this->_missingPassphrases;
    }
}
