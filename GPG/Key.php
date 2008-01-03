<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Contains a data class representing GPG keys and constants
 * representing GPG algorithms
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
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */

// {{{ class Crypt_GPG_Key

/**
 * A data class for GPG key information
 *
 * This class is used to store the results of the {@link Crypt_GPG::listKeys()}
 * method. See the first section of doc/DETAILS in the
 * {@link http://www.gnupg.org/download/ GPG package} for a detailed
 * description of these values.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @copyright 2005 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @see       Crypt_GPG::listKeys()
 */
class Crypt_GPG_Key
{
    // {{{ class constants

    /**
     * RSA encryption algorithm
     */
    const ALGORITHM_RSA = 1;

    /**
     * Elgamal encryption algorithm (encryption only)
     */
    const ALGORITHM_ELGAMAL_ENC = 16;

    /**
     * DSA encryption algorithm (sometimes called DH, sign only)
     */
    const ALGORITHM_DSA = 17;

    /**
     * Elgamal encryption algorithm (signage and encryption - should not be
     * used).
     */
    const ALGORITHM_ELGAMAL_ENC_SGN = 20;

    // }}}
    // {{{ class properties

    /**
     * The id of this key
     *
     * @var string
     */
    public $id = '';

    /**
     * The fingerprint of this key
     *
     * @var string
     */
    public $fingerprint = '';

    /**
     * Length of this key in bits
     *
     * @var int
     */
    public $length = 0;

    /**
     * The algorithm used to create this key
     *
     * The value is one of the Crypt_GPG_Key::ALGORITHM_* constants.
     *
     * @var int
     */
    public $algorithm = 0;

    /**
     * Date this key was created
     *
     * This is a Unix timestamp.
     *
     * @var integer
     */
    public $creation_date = 0;

    /**
     * Date this key expires
     *
     * This is a Unix timestamp. If this key does not expire, this will be
     * zero.
     *
     * @var integer
     */
    public $expiration_date = 0;

    /**
     * The user ids associated with this key
     *
     * @var array
     */
    public $user_ids = array();

    // }}}
}

// }}}

?>
