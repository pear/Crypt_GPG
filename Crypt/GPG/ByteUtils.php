<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

class Crypt_GPG_ByteUtils
{
    // {{{ strlen()

    /**
     * Gets the length of a string in bytes
     *
     * This is used for stream-based communication with the GPG subprocess.
     *
     * @param string $string the string for which to get the length.
     *
     * @return integer the length of the string in bytes.
     */
    public static function strlen($string)
    {
        return mb_strlen($string, '8bit');
    }

    // }}}
    // {{{ substr()

    /**
     * Gets the substring of a string in bytes
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
     */
    public static function substr($string, $start, $length = null)
    {
        if ($length === null) {
            return mb_substr(
                $string,
                $start,
                self::strlen($string) - $start, '8bit'
            );
        }

        return mb_substr($string, $start, $length, '8bit');
    }

    // }}}
}

?>
