<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * A data class representing GPG signatures
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
 * @link      http://pear.php.net/package/Crypt_GPG
 */

// {{{ class Crypt_GPG_Signature

/**
 * A data class for GPG signature information
 *
 * This class is used to store the results of the Crypt_GPG::verify() method.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2007 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @see       Crypt_GPG::verify()
 */
class Crypt_GPG_Signature
{
    // {{{ class properties

    /**
     * A base64 string containing the signature id for signatures
     * of class 0 or 1 which have been verified ok
     *
     * This id is used to prevent replay attacks and is not present for all
     * signature types.
     *
     * @var string
     */
    public $id = '';

    /**
     * The signature fingerprint in hexidecimal
     *
     * @var string
     */
    public $fingerprint = '';

    /**
     * The creation date of this signature
     *
     * This is a Unix timestamp.
     *
     * @var integer
     */
    public $creation_date = 0;

    /**
     * The expiration date of the signature
     *
     * This is a Unix timestamp. If this key does not expire, this will be
     * zero.
     *
     * @var integer
     */
    public $expiration_date = 0;

    /**
     * The id of the key used to create this signature
     *
     * @var string
     */
    public $key_id = '';

    /**
     * The primary user associated with this signature
     *
     * @var string
     */
    public $user_id = '';

    /**
     * Whether or not this signature is valid
     *
     * @var boolean
     */
    public $valid = false;

    // }}}
}

// }}}

?>
