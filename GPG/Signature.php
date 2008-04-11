<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * A class representing GPG signatures
 *
 * This file contains a data class representing a GPG signature.
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
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

/**
 * User id class definition
 */
require_once 'Crypt/GPG/UserId.php';

// {{{ class Crypt_GPG_Signature

/**
 * A class for GPG signature information
 *
 * This class is used to store the results of the Crypt_GPG::verify() method.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @see       Crypt_GPG::verify()
 */
class Crypt_GPG_Signature
{
    // {{{ class properties

    /**
     * A base64-encoded string containing a unique id for this signature if
     * this signature has been verified as ok
     *
     * This id is used to prevent replay attacks and is not present for all
     * types of signatures.
     *
     * @var string
     */
    private $_id = '';

    /**
     * The fingerprint of the key used to create the signature
     *
     * @var string
     */
    private $_keyFingerprint = '';

    /**
     * The creation date of this signature
     *
     * This is a Unix timestamp.
     *
     * @var integer
     */
    private $_creationDate = 0;

    /**
     * The expiration date of the signature
     *
     * This is a Unix timestamp. If this signature does not expire, this will
     * be zero.
     *
     * @var integer
     */
    private $_expirationDate = 0;

    /**
     * The user id associated with this signature
     *
     * @var Crypt_GPG_UserId
     */
    private $_userId = null;

    /**
     * Whether or not this signature is valid
     *
     * @var boolean
     */
    private $_isValid = false;

    // }}}
    // {{{ getId()

    /**
     * Gets the id of this signature
     *
     * @return string a base64-encoded string containing a unique id for this
     *                signature. This id is used to prevent replay attacks and
     *                is not present for all types of signatures.
     */
    public function getId()
    {
        return $this->_id;
    }

    // }}}
    // {{{ getKeyFingerprint()

    /**
     * Gets the fingerprint of the key used to create this signature
     *
     * @return string the fingerprint of the key used to create this signature.
     */
    public function getKeyFingerprint()
    {
        return $this->_keyFingerprint;
    }

    // }}}
    // {{{ getCreationDate()

    /**
     * Gets the creation date of this signature
     *
     * @return integer the creation date of this signature. This is a Unix
     *                 timestamp.
     */
    public function getCreationDate()
    {
        return $this->_creationDate;
    }

    // }}}
    // {{{ getExpirationDate()

    /**
     * Gets the expiration date of the signature
     *
     * @return integer the expiration date of this signature. This is a Unix
     *                 timestamp. If this signature does not expire, this will
     *                 be zero.
     */
    public function getExpirationDate()
    {
        return $this->_expirationDate;
    }

    // }}}
    // {{{ getUserId()

    /**
     * Gets the user id associated with this signature
     *
     * @return Crypt_GPG_UserId the user id associated with this signature.
     */
    public function getUserId()
    {
        return $this->_userId;
    }

    // }}}
    // {{{ isValid()

    /**
     * Gets whether or no this signature is valid
     *
     * @return boolean true if this signature is valid and false if it is not.
     */
    public function isValid()
    {
        return $this->_isValid;
    }

    // }}}
    // {{{ setId()

    /**
     * Sets the id of this signature
     *
     * @param string $id a base64-encoded string containing a unique id for
     *                   this signature.
     *
     * @return void
     *
     * @see Crypt_GPG_Signature::getId()
     */
    public function setId($id)
    {
        $this->_id = strval($id);
    }

    // }}}
    // {{{ setKeyFingerprint()

    /**
     * Sets the key fingerprint of this signature
     *
     * @param string $fingerprint the key fingerprint of this signature. This
     *                            is the fingerprint of the primary key used to
     *                            sign this signature.
     *
     * @return void
     */
    public function setKeyFingerprint($fingerprint)
    {
        $this->_keyFingerprint = strval($fingerprint);
    }

    // }}}
    // {{{ setCreationDate()

    /**
     * Sets the creation date of this signature
     *
     * @param integer $creationDate the creation date of this signature. This
     *                              is a Unix timestamp.
     *
     * @return void
     */
    public function setCreationDate($creationDate)
    {
        $this->_creationDate = intval($creationDate);
    }

    // }}}
    // {{{ setExpirationDate()

    /**
     * Sets the expiration date of this signature
     *
     * @param integer $expirationDate the expiration date of this signature.
     *                                This is a Unix timestamp. Specify zero if
     *                                this signature does not expire.
     *
     * @return void
     */
    public function setExpirationDate($expirationDate)
    {
        $this->_expirationDate = intval($expirationDate);
    }

    // }}}
    // {{{ setUserId()

    /**
     * Sets the user id associated with this signature
     *
     * @param Crypt_GPG_UserId $userId the user id associated with this
     *                                 signature.
     *
     * @return void
     */
    public function setUserId(Crypt_GPG_UserId $userId)
    {
        $this->_userId = $userId;
    }

    // }}}
    // {{{ setIsValid()

    /**
     * Sets whether or not this signature is valid
     *
     * @param boolean $isValid true if this signature is valid and false if it
     *                         is not.
     *
     * @return void
     */
    public function setIsValid($isValid)
    {
        $this->_isValid = ($isValid) ? true : false;
    }

    // }}}
}

// }}}

?>
