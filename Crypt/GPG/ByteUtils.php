<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

class Crypt_GPG_ByteUtils
{
    // {{{ private properties

    /**
     * Cached value indicating whether or not mbstring function overloading is
     * on for strlen
     *
     * This is cached for optimal performance inside I/O loops.
     *
     * @var boolean
     *
     * @see Crypt_GPG_ByteUtils::_byteLength()
     * @see Crypt_GPG_ByteUtils::_byteSubstring()
     */
    private static $_mbStringOverload = null;

    // }}}
    // {{{ strlen()

    /**
     * Gets the length of a string in bytes even if mbstring function
     * overloading is turned on
     *
     * This is used for stream-based communication with the GPG subprocess.
     *
     * @param string $string the string for which to get the length.
     *
     * @return integer the length of the string in bytes.
     *
     * @see Crypt_GPG_ByteUtils::$_mbStringOverload
     */
    public static function strlen($string)
    {
        if (self::$_mbStringOverload === null) {
            self::$_mbStringOverload = self::getMBStringOverload();
        }

        if (self::$_mbStringOverload) {
            return mb_strlen($string, '8bit');
        }

        return strlen((binary)$string);
    }

    // }}}
    // {{{ substr()

    /**
     * Gets the substring of a string in bytes even if mbstring function
     * overloading is turned on
     *
     * This is used for stream-based communication with the GPG subprocess.
     *
     * @param string  $string the input string.
     * @param integer $start  the starting point at which to get the substring.
     * @param integer $length optional. The length of the substring.
     *
     * @return string the extracted part of the string. Unlike the default PHP
     *                <kbd>substr()</kbd> function, the returned value is
     *                always a string and never false.
     *
     * @see Crypt_GPG_ByteUtils::$_mbStringOverload
     */
    public static function substr($string, $start, $length = null)
    {
        if (self::$_mbStringOverload === null) {
            self::$_mbStringOverload = self::getMBStringOverload();
        }

        if (self::$_mbStringOverload) {
            if ($length === null) {
                return mb_substr(
                    $string,
                    $start,
                    self::strlen($string) - $start, '8bit'
                );
            }

            return mb_substr($string, $start, $length, '8bit');
        }

        if ($length === null) {
            return (string)substr((binary)$string, $start);
        }

        return (string)substr((binary)$string, $start, $length);
    }

    // }}}
    // {{{ getMBStringOverload()

    /**
     * Gets the status of mbstring function overloading
     *
     * @return boolean true if mbstring function overloading is enabled for
     *                 strlen and substr. False if not.
     */
    protected static function getMBStringOverload()
    {
        return (extension_loaded('mbstring')
            && (ini_get('mbstring.func_overload') & 0x02) === 0x02);
    }

    // }}}
}

?>
