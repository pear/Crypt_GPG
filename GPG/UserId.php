<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Contains a data class representing a GPG user id
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
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 */

// {{{ class Crypt_GPG_UserId

/**
 * A class for GPG user id information
 *
 * This class is used to store the results of the {@link Crypt_GPG::getKeys()}
 * method. User id objects are members of a {@link Crypt_GPG_Key} object.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @see       Crypt_GPG::getKeys()
 * @see       Crypt_GPG_Key::getUserIds()
 */
class Crypt_GPG_UserId
{
    // {{{ class properties

    /**
     * The name field of this user id
     *
     * @var string
     */
    private $_name = '';

    /**
     * The comment field of this user id
     *
     * @var string
     */
    private $_comment = '';

    /**
     * The email field of this user id
     *
     * @var string
     */
    private $_email = '';

    /**
     * Whether or not this user id is revoked
     *
     * @var boolean
     */
    private $_is_revoked = false;

    /**
     * Whether or not this user id is valid
     *
     * @var boolean
     */
    private $_is_valid = true;

    // }}}
    // {{{ getName()

    /**
     * Gets the name field of this user id
     *
     * @return string the name field of this user id.
     */
    public function getName()
    {
        return $this->_name;
    }

    // }}}
    // {{{ getComment()

    /**
     * Gets the comments field of this user id
     *
     * @return string the comments field of this user id.
     */
    public function getComment()
    {
        return $this->_comment;
    }

    // }}}
    // {{{ getEmail()

    /**
     * Gets the email field of this user id
     *
     * @return string the email field of this user id.
     */
    public function getEmail()
    {
        return $this->_email;
    }

    // }}}
    // {{{ isRevoked()

    /**
     * Gets whether or not this user id is revoked
     *
     * @return boolean true if this user id is revoked and false if it is not.
     */
    public function isRevoked()
    {
        return $this->_is_revoked;
    }

    // }}}
    // {{{ isValid()

    /**
     * Gets whether or not this user id is valid
     *
     * @return boolean true if this user id is valid and false if it is not.
     */
    public function isValid()
    {
        return $this->_is_valid;
    }

    // }}}
    // {{{ __toString()

    /**
     * Gets a string representation of this user id
     *
     * The string is formatted as: 'name (comment) <email>'.
     *
     * @return string a string representation of this user id.
     */
    public function __toString()
    {
        $components = array();

        if (strlen($this->_name) > 0) {
            $components[] = $this->_name;
        }

        if (strlen($this->_comment) > 0) {
            $components[] = '(' . $this->_comment . ')';
        }

        if (strlen($this->_email) > 0) {
            $components[] = '<' . $this->_email. '>';
        }

        return implode(' ', $components);
    }

    // }}}
    // {{{ setName()

    /**
     * Sets the name field of this user id
     *
     * @param string $name the name field of this user id.
     *
     * @return void
     */
    public function setName($name)
    {
        $this->_name = strval($name);
    }

    // }}}
    // {{{ setComment()

    /**
     * Sets the comment field of this user id
     *
     * @param string $comment the comment field of this user id.
     *
     * @return void
     */
    public function setComment($comment)
    {
        $this->_comment = strval($comment);
    }

    // }}}
    // {{{ setEmail()

    /**
     * Sets the email field of this user id
     *
     * @param string $email the email field of this user id.
     *
     * @return void
     */
    public function setEmail($email)
    {
        $this->_email = strval($email);
    }

    // }}}
    // {{{ setRevoked()

    /**
     * Sets whether or not this user id is revoked
     *
     * @param boolean $is_revoked whether or not this user id is revoked.
     *
     * @return void
     */
    public function setRevoked($is_revoked)
    {
        $this->_is_revoked = ($is_revoked) ? true : false;
    }

    // }}}
    // {{{ setValid()

    /**
     * Sets whether or not this user id is valid
     *
     * @param boolean $is_valid whether or not this user id is valid.
     *
     * @return void
     */
    public function setValid($is_valid)
    {
        $this->_is_valid = ($is_valid) ? true : false;
    }

    // }}}
}

// }}}

?>
