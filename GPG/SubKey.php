<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Contains a class representing GPG sub-keys and constants for GPG algorithms
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
 * @author    Michael Gauthier <mike@silverorange.com>
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

// {{{ class Crypt_GPG_SubKey

/**
 * A class for GPG sub-key information
 *
 * This class is used to store the results of the {@link Crypt_GPG::getKeys()}
 * method. Sub-key objects are members of a {@link Crypt_GPG_Key} object.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @see       Crypt_GPG::getKeys()
 * @see       Crypt_GPG_Key::getSubKeys()
 */
class Crypt_GPG_SubKey
{
    // {{{ class constants

    /**
     * RSA encryption algorithm.
     */
    const ALGORITHM_RSA             = 1;

    /**
     * Elgamal encryption algorithm (encryption only).
     */
    const ALGORITHM_ELGAMAL_ENC     = 16;

    /**
     * DSA encryption algorithm (sometimes called DH, sign only).
     */
    const ALGORITHM_DSA             = 17;

    /**
     * Elgamal encryption algorithm (signage and encryption - should not be
     * used).
     */
    const ALGORITHM_ELGAMAL_ENC_SGN = 20;

    // }}}
    // {{{ class properties

    /**
     * The id of this sub-key
     *
     * @var string
     */
    private $_id = '';

    /**
     * The algorithm used to create this sub-key
     *
     * The value is one of the Crypt_GPG_SubKey::ALGORITHM_* constants.
     *
     * @var integer
     */
    private $_algorithm = 0;

    /**
     * The fingerprint of this sub-key
     *
     * @var string
     */
    private $_fingerprint = '';

    /**
     * Length of this sub-key in bits
     *
     * @var integer
     */
    private $_length = 0;

    /**
     * Date this sub-key was created
     *
     * This is a Unix timestamp.
     *
     * @var integer
     */
    private $_creation_date = 0;

    /**
     * Date this sub-key expires
     *
     * This is a Unix timestamp. If this sub-key does not expire, this will be
     * zero.
     *
     * @var integer
     */
    private $_expiration_date = 0;

    /**
     * Whether or not this sub-key can sign data
     *
     * @var boolean
     */
    private $_can_sign = false;

    /**
     * Whether or not this sub-key can encrypt data
     *
     * @var boolean
     */
    private $_can_encrypt = false;

    /**
     * Whether or not the private key for this sub-key exists in the keyring
     *
     * @var boolean
     */
    private $_has_private = false;

    // }}}
    // {{{ getId()

    /**
     * Gets the id of this sub-key
     *
     * @return string the id of this sub-key.
     */
    public function getId()
    {
        return $this->_id;
    }

    // }}}
    // {{{ getAlgorithm()

    /**
     * Gets the algorithm used by this sub-key
     *
     * The algorithm should be one of the Crypt_GPG_SubKey::ALGORITHM_*
     * constants.
     *
     * @return integer the algorithm used by this sub-key.
     */
    public function getAlgorithm()
    {
        return $this->_algorithm;
    }

    // }}}
    // {{{ getCreationDate()

    /**
     * Gets the creation date of this sub-key
     *
     * This is a Unix timestamp.
     *
     * @return integer the creation date of this sub-key.
     */
    public function getCreationDate()
    {
        return $this->_creation_date;
    }

    // }}}
    // {{{ getExpirationDate()

    /**
     * Gets the date this sub-key expires
     *
     * This is a Unix timestamp. If this sub-key does not expire, this will be
     * zero.
     *
     * @return integer the date this sub-key expires.
     */
    public function getExpirationDate()
    {
        return $this->_expiration_date;
    }

    // }}}
    // {{{ getFingerprint()

    /**
     * Gets the fingerprint of this sub-key
     *
     * @return string the fingerprint of this sub-key.
     */
    public function getFingerprint()
    {
        return $this->_fingerprint;
    }

    // }}}
    // {{{ getLength()

    /**
     * Gets the length of this sub-key in bits
     *
     * @return integer the length of this sub-key in bits.
     */
    public function getLength()
    {
        return $this->_length;
    }

    // }}}
    // {{{ canSign()

    /**
     * Gets whether or not this sub-key can sign data
     *
     * @return boolean true if this sub-key can sign data and false if this
     *                 sub-key can not sign data.
     */
    public function canSign()
    {
        return $this->_can_sign;
    }

    // }}}
    // {{{ canEncrypt()

    /**
     * Gets whether or not this sub-key can encrypt data
     *
     * @return boolean true if this sub-key can encrypt data and false if this
     *                 sub-key can not encrypt data.
     */
    public function canEncrypt()
    {
        return $this->_can_encrypt;
    }

    // }}}
    // {{{ hasPrivate()

    /**
     * Gets whether or not the private key for this sub-key exists in the
     * keyring
     *
     * @return boolean true the private key for this sub-key exists in the
     *                 keyring and false if it does not.
     */
    public function hasPrivate()
    {
        return $this->_has_private;
    }

    // }}}
    // {{{ setCreationDate()

    /**
     * Sets the creation date of this sub-key
     *
     * The creation date is a Unix timestamp.
     *
     * @param integer $creation_date the creation date of this sub-key.
     *
     * @return void
     */
    public function setCreationDate($creation_date)
    {
        $this->_creation_date = intval($creation_date);
    }

    // }}}
    // {{{ setExpirationDate()

    /**
     * Sets the expiration date of this sub-key
     *
     * The expiration date is a Unix timestamp. Specify zero if this sub-key
     * does not expire.
     *
     * @param integer $expiration_date the expiration date of this sub-key.
     *
     * @return void
     */
    public function setExpirationDate($expiration_date)
    {
        $this->_expiration_date = intval($expiration_date);
    }

    // }}}
    // {{{ setId()

    /**
     * Sets the id of this sub-key
     *
     * @param string $id the id of this sub-key.
     *
     * @return void
     */
    public function setId($id)
    {
        $this->_id = strval($id);
    }

    // }}}
    // {{{ setAlgorithm()

    /**
     * Sets the algorithm used by this sub-key
     *
     * @param integer $algorithm the algorithm used by this sub-key.
     *
     * @return void
     */
    public function setAlgorithm($algorithm)
    {
        $this->_algorithm = intval($algorithm);
    }

    // }}}
    // {{{ setFingerprint()

    /**
     * Sets the fingerprint of this sub-key
     *
     * @param string $fingerprint the fingerprint of this sub-key.
     *
     * @return void
     */
    public function setFingerprint($fingerprint)
    {
        $this->_fingerprint = strval($fingerprint);
    }

    // }}}
    // {{{ setLength()

    /**
     * Sets the length of this sub-key in bits
     *
     * @param integer $length the length of this sub-key in bits.
     *
     * @return void
     */
    public function setLength($length)
    {
        $this->_length = intval($length);
    }

    // }}}
    // {{{ setCanSign()

    /**
     * Sets whether of not this sub-key can sign data
     *
     * @param boolean $can_sign true if this sub-key can sign data and false if
     *                          it can not.
     *
     * @return void
     */
    public function setCanSign($can_sign)
    {
        $this->_can_sign = ($can_sign) ? true : false;
    }

    // }}}
    // {{{ setCanEncrypt()

    /**
     * Sets whether of not this sub-key can encrypt data
     *
     * @param boolean $can_encrypt true if this sub-key can encrypt data and
     *                             false if it can not.
     *
     * @return void
     */
    public function setCanEncrypt($can_encrypt)
    {
        $this->_can_encrypt = ($can_encrypt) ? true : false;
    }

    // }}}
    // {{{ setHasPrivate()

    /**
     * Sets whether of not the private key for this sub-key exists in the
     * keyring
     *
     * @param boolean $has_private true if the private key for this sub-key
     *                             exists in the keyring and false if it does
     *                             not.
     *
     * @return void
     */
    public function setHasPrivate($has_private)
    {
        $this->_has_private = ($has_private) ? true : false;
    }

    // }}}
}

// }}}

?>
