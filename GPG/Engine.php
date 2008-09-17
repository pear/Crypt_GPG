<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Crypt_GPG is a package to use GPG from PHP
 *
 * This file contains an engine that handles GPG subprocess control and I/O.
 * PHP's process manipulation functions are used to handle the GPG subprocess.
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
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @version   CVS: $Id$
 * @link      http://pear.php.net/package/Crypt_GPG
 * @link      http://www.gnupg.org/
 */

/**
 * Crypt_GPG driver base class.
 */
require_once 'Crypt/GPG.php';

/**
 * GPG exception classes.
 */
require_once 'Crypt/GPG/Exceptions.php';

/**
 * Standard PEAR exception is used if GPG binary is not found.
 */
require_once 'PEAR/Exception.php';

// {{{ class Crypt_GPG_Engine

/**
 * Native PHP Crypt_GPG I/O engine
 *
 * This engine uses PHP's native process control functions to directly control
 * the GPG process. The GPG executable is required to be on the system.
 *
 * All data is passed to the GPG subprocess using file descriptors. This is the
 * most secure method of passing data to the GPG subprocess.
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Nathan Fredrickson <nathan@silverorange.com>
 * @author    Michael Gauthier <mike@silverorange.com>
 * @copyright 2005-2008 silverorange
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 * @link      http://www.gnupg.org/
 */
class Crypt_GPG_Engine
{
    // {{{ constants

    /**
     * Size of data chunks that are sent to and retrieved from the IPC pipes.
     *
     * PHP reads 8192 bytes. If this is set to less than 8192, PHP reads 8192
     * and buffers the rest so we might as well just read 8192.
     *
     * Using values other than 8192 also triggers PHP bugs.
     *
     * @see http://bugs.php.net/bug.php?id=35224
     */
    const CHUNK_SIZE = 8192;

    /**
     * Standard input file descriptor. This is used to pass data to the GPG
     * process.
     */
    const FD_INPUT = 0;

    /**
     * Standard output file descriptor. This is used to receive normal output
     * from the GPG process.
     */
    const FD_OUTPUT = 1;

    /**
     * Standard output file descriptor. This is used to receive error output
     * from the GPG process.
     */
    const FD_ERROR = 2;

    /**
     * GPG status output file descriptor. The status file descriptor outputs
     * detailed information for many GPG commands. See the second section of
     * the file doc/DETAILS in the
     * {@link http://www.gnupg.org/download/ GPG package} for a detailed
     * description of GPG's status output.
     */
    const FD_STATUS = 3;

    /**
     * Command input file descriptor. This is used for methods requiring
     * passphrases.
     */
    const FD_COMMAND = 4;

    /**
     * Extra message input file descriptor. This is used for passing signed
     * data when verifying a detached signature.
     */
    const FD_MESSAGE = 5;

    // }}}
    // {{{ private class properties

    /**
     * Whether or not to use debugging mode
     *
     * When set to true, every GPG command is echoed before it is run. Sensitive
     * data is always handled using pipes and is not specified as part of the
     * command. As a result, sensitive data is never displayed when debug is
     * enabled. Sensitive data includes private key data and passphrases.
     *
     * Debugging is off by default.
     *
     * @var boolean
     */
    private $_debug = false;

    /**
     * Location of GPG binary
     *
     * @var string
     * @see Crypt_GPG_Engine::__construct()
     * @see Crypt_GPG_Engine::_getBinary()
     */
    private $_gpgBinary = '';

    /**
     * Directory containing the GPG key files
     *
     * This property only contains the path when the <i>homedir</i> option
     * is specified in the constructor.
     *
     * @var string
     * @see Crypt_GPG_Engine::__construct()
     */
    private $_homedir = '';

    /**
     * Array of pipes used for communication with the GPG binary
     *
     * This is an array of file descriptor resources.
     *
     * @var array
     */
    private $_pipes = array();

    /**
     * Array of currently opened pipes
     *
     * This array is used to keep track of remaining opened pipes so they can
     * be closed when the GPG subprocess is finished. This array is a subset of
     * the {@link Crypt_GPG_Engine::$_pipes} array and contains opened file
     * descriptor resources.
     *
     * @var array
     * @see Crypt_GPG_Engine::_closePipe()
     */
    private $_openPipes = array();

    /**
     * A handle for the GPG process
     *
     * @var resource
     */
    private $_process = null;

    /**
     * Whether or not the operating system is Darwin (OS X)
     *
     * @var boolean
     */
    private $_isDarwin = false;

    /**
     * @var string
     *
     * @see Crypt_GPG_Engine::sendCommand()
     */
    private $_commandBuffer = '';

    /**
     * @var array
     *
     * @see Crypt_GPG_Engine::addStatusHandler()
     */
    private $_statusHandlers = array();

    /**
     * @var array
     *
     * @see Crypt_GPG_Engine::addErrorHandler()
     */
    private $_errorHandlers = array();

    /**
     * @var integer
     */
    private $_errorCode = Crypt_GPG::ERROR_NONE;

    /**
     * @var integer
     */
    private $_needPassphrase = 0;

    /**
     * The input source
     *
     * This is data to send to GPG.
     *
     * @var string|resource
     *
     * @see Crypt_GPG_Engine::setInput()
     *
     * All arguments may either be strings or streams. Output from this method
     * is stored in in the strings or streams passed by reference in the
     * appropriate parameters. All parameters are passed by reference
     *
     * @param string|resource $input   the input source. This is data to send
     *                                 to GPG. If there is no data to send to
     *                                 GPG, specify null.
     * @param string|resource $output  the output location. This is where the
     *                                 output of GPG is sent.
     * @param string|resource $message the extra message input source. Detached
     *                                 signature data should be specified here.
     *                                 If there is no message input, specify
     *                                 null.
     */
    private $_input = null;

    private $_message = null;

    private $_output = '';

    /**
     * The GPG operation to execute
     *
     * @var string
     *
     * @see Crypt_GPG_Engine::setOperation()
     */
    private $_operation;

    /**
     * Arguments for the current operation
     *
     * @var array
     *
     * @see Crypt_GPG_Engine::setOperation()
     */
    private $_arguments = array();

    /**
     * Cached value indicating whether or not mbstring function overloading is
     * on for strlen
     *
     * This is cached for optimal performance inside the I/O loop.
     *
     * @see Crypt_GPG_Engine::_byteLength()
     * @see Crypt_GPG_Engine::_byteSubstring()
     */
    private static $_mbStringOverload = null;

    // }}}
    // {{{ __construct()

    /**
     * Creates a new GPG engine
     *
     * Available options:
     *
     * - string  homedir:    The directory where the GPG keyring files are
     *                       stored. If not specified, GPG uses the default of
     *                       $HOME/.gnupg, where $HOME is the present user's
     *                       home directory. This option only needs to be
     *                       specified when $HOME/.gnupg is inappropriate.
     *
     * - string  gpgBinary:  The location of the GPG binary. If not specified,
     *                       the driver attempts to auto-detect the GPG binary
     *                       location using a list of known default locations
     *                       for the current operating system.
     *
     * - boolean debug:      Whether or not to use debug mode. See
     *                       {@link Crypt_GPG_Engine::$_debug}.
     *
     * @param array $options optional. An array of options used to create the
     *                       GPG object. All options must be optional and are
     *                       represented as key-value pairs.
     *
     * @throws PEAR_Exception if the provided 'gpgBinary' is invalid; or if no
     *         'gpgBinary' is provided and no suitable binary could be found.
     */
    public function __construct(array $options = array())
    {
        $this->_isDarwin = (strncmp(strtoupper(PHP_OS), 'DARWIN', 6) === 0);

        // populate mbstring overloading cache if not set
        if (self::$_mbStringOverload === null) {
            self::$_mbStringOverload = (extension_loaded('mbstring')
                && (ini_get('mbstring.func_overload') & 0x02) === 0x02);
        }

        if (array_key_exists('homedir', $options)) {
            $this->_homedir = (string)$options['homedir'];
        }

        if (array_key_exists('gpgBinary', $options)) {
            $this->_gpgBinary = (string)$options['gpgBinary'];
        } else {
            $this->_gpgBinary = $this->_getBinary();
        }

        if ($this->_gpgBinary == '' || !is_executable($this->_gpgBinary)) {
            throw new PEAR_Exception('GPG binary not found. If you are sure '.
                'the GPG binary is installed, please specify the location of '.
                'the GPG binary using the \'gpgBinary\' driver option.');
        }

        if (array_key_exists('debug', $options)) {
            $this->_debug = (boolean)$options['debug'];
        }
    }

    // }}}
    // {{{ __destruct()

    /**
     * Closes open GPG subprocesses when this object is destroyed
     *
     * Subprocesses should never be left open by this class unless there is
     * an unknown error and unexpected script termination occurs.
     */
    public function __destruct()
    {
        $this->_closeSubprocess();
    }

    // }}}
    // {{{ addErrorHandler()

    /**
     * Adds an error handler method
     *
     * The method is run every time a new error line is received from the GPG
     * subprocess. The handler method must accept the error line to be handled
     * as its first parameter.
     *
     * @param callback $callback the callback method to use.
     * @param array    $args     optional. Additional arguments to pass as
     *                           parameters to the callback method.
     *
     * @return void
     */
    public function addErrorHandler($callback, array $args = array())
    {
        $this->_errorHandlers[] = array(
            'callback' => $callback,
            'args'     => $args
        );
    }

    // }}}
    // {{{ addStatusHandler()

    /**
     * Adds a status handler method
     *
     * The method is run every time a new status line is received from the
     * GPG subprocess. The handler method must accept the status line to be
     * handled as its first parameter.
     *
     * @param callback $callback the callback method to use.
     * @param array    $args     optional. Additional arguments to pass as
     *                           parameters to the callback method.
     *
     * @return void
     */
    public function addStatusHandler($callback, array $args = array())
    {
        $this->_statusHandlers[] = array(
            'callback' => $callback,
            'args'     => $args
        );
    }

    // }}}
    // {{{ sendCommand()

    /**
     * Sends a command to the GPG subprocess over the command file-descriptor
     * pipe
     *
     * @param string $command the command to send.
     *
     * @return void
     *
     * @sensitive $command
     */
    public function sendCommand($command)
    {
        if (array_key_exists(self::FD_COMMAND, $this->_openPipes)) {
            $this->_commandBuffer .= $command . PHP_EOL;
        }
    }

    // }}}
    // {{{ reset()

    /**
     * Resets the GPG engine, preparing it for a new operation
     *
     * @return void
     *
     * @see Crypt_GPG_Engine::run()
     * @see Crypt_GPG_Engine::setOperation()
     */
    public function reset()
    {
        $this->_operation      = '';
        $this->_arguments      = array();
        $this->_input          = null;
        $this->_message        = null;
        $this->_output         = '';
        $this->_errorCode      = Crypt_GPG::ERROR_NONE;
        $this->_needPassphrase = 0;
        $this->_commandBuffer  = '';

        $this->_statusHandlers = array();
        $this->_errorHandlers  = array();

        $this->addStatusHandler(array($this, '_handleErrorStatus'));
        $this->addErrorHandler(array($this, '_handleErrorError'));

        if ($this->_debug) {
            $this->addStatusHandler(array($this, '_handleDebugStatus'));
            $this->addStatusHandler(array($this, '_handleDebugError'));
        }
    }

    // }}}
    // {{{ run()

    /**
     * Runs the current GPG operation
     *
     * This creates and manages the GPG subprocess.
     *
     * The operation must be set with {@link Crypt_GPG_Engine::setOperation()}
     * before this method is called.
     *
     * @return void
     *
     * @throws Crypt_GPG_InvalidOperationException if no operation is specified.
     *
     * @see Crypt_GPG_Engine::reset()
     * @see Crypt_GPG_Engine::setOperation()
     */
    public function run()
    {
        if ($this->_operation === '') {
            throw new Crypt_GPG_InvalidOperationException('No GPG operation ' .
                'specified. Use Crypt_GPG_Engine::setOperation() before ' .
                'calling Crypt_GPG_Engine::run().');
        }

        $this->_openSubprocess();
        $this->_process();
        $this->_closeSubprocess();
    }

    // }}}
    // {{{ getErrorCode()

    /**
     * Gets the error code of the last executed operation
     *
     * This value is only meaningful after {@link Crypt_GPG_Engine::run()} has
     * been executed.
     *
     * @return integer the error code of the last executed operation.
     */
    public function getErrorCode()
    {
        return $this->_errorCode;
    }

    // }}}
    // {{{ setInput()

    /**
     * Sets the input source for the current GPG operation
     *
     * @param string|resource &$input either a reference to the string
     *                                containing the input data or an open
     *                                stream resource containing the input
     *                                data.
     *
     * @return void
     */
    public function setInput(&$input)
    {
        $this->_input =& $input;
    }

    // }}}
    // {{{ setMessage()

    /**
     * Sets the message source for the current GPG operation
     *
     * @param string|resource &$message either a reference to the string
     *                                  containing the message data or an open
     *                                  stream resource containing the message
     *                                  data.
     *
     * @return void
     */
    public function setMessage(&$message)
    {
        $this->_message =& $message;
    }

    // }}}
    // {{{ setOutput()

    /**
     * Sets the output destination for the current GPG operation
     *
     * @param string|resource &$output either a reference to the string in
     *                                 which to store GPG output or an open
     *                                 stream resource to which the output data
     *                                 should be written.
     *
     * @return void
     */
    public function setOutput(&$output)
    {
        $this->_output =& $output;
    }

    // }}}
    // {{{ setOperation()

    /**
     * Sets the operation to perform
     *
     * @param string $operation the operation to perform. This should be one
     *                          of GPG's operations. For example,
     *                          <code>--encrypt</code>, <code>--decrypt</code>,
     *                          <code>--sign</code>, etc.
     * @param array  $arguments optional. Additional arguments for the GPG
     *                          subprocess. See the GPG manual for specific
     *                          values.
     *
     * @return void
     *
     * @see Crypt_GPG_Engine::reset()
     * @see Crypt_GPG_Engine::run()
     */
    public function setOperation($operation, array $arguments = array())
    {
        $this->_operation = $operation;
        $this->_arguments = $arguments;
    }

    // }}}
    // {{{ _handleErrorStatus()

    /**
     * Handles error values in the status output from GPG
     *
     * This method is responsible for setting the
     * {@link Crypt_GPG_Engine::$_errorCode}. See
     * <strong>doc/DETAILS</strong> in the
     * {@link http://www.gnupg.org/download/ GPG distribution} for detailed
     * info on GPG's status output.
     *
     * @param string $line the status line to handle.
     *
     * @return void
     */
    private function _handleErrorStatus($line)
    {
        $tokens = explode(' ', $line);
        switch ($tokens[0]) {
        case 'BAD_PASSPHRASE':
            $this->_errorCode = Crypt_GPG::ERROR_BAD_PASSPHRASE;
            break;

        case 'MISSING_PASSPHRASE':
            $this->_errorCode = Crypt_GPG::ERROR_MISSING_PASSPHRASE;
            break;

        case 'NODATA':
            $this->_errorCode = Crypt_GPG::ERROR_NO_DATA;
            break;

        case 'DELETE_PROBLEM':
            if ($tokens[1] == '1') {
                $this->_errorCode = Crypt_GPG::ERROR_KEY_NOT_FOUND;
                break;
            } elseif ($tokens[1] == '2') {
                $this->_errorCode = Crypt_GPG::ERROR_DELETE_PRIVATE_KEY;
                break;
            }
            break;

        case 'IMPORT_RES':
            if ($tokens[12] > 0) {
                $this->_errorCode = Crypt_GPG::ERROR_DUPLICATE_KEY;
            }
            break;

        case 'NEED_PASSPHRASE':
            $this->_needPassphrase++;
            break;

        case 'GOOD_PASSPHRASE':
            $this->_needPassphrase--;
            break;

        }
    }

    // }}}
    // {{{ _handleErrorError()

    /**
     * Handles error values in the error output from GPG
     *
     * This method is responsible for setting the
     * {@link Crypt_GPG_Engine::$_errorCode}.
     *
     * @param string $line the error line to handle.
     *
     * @return void
     */
    private function _handleErrorError($line)
    {
        if ($this->_errorCode === Crypt_GPG::ERROR_NONE) {
            $pattern = '/no valid OpenPGP data found/';
            if (preg_match($pattern, $line) === 1) {
                $this->_errorCode = Crypt_GPG::ERROR_NO_DATA;
            }
        }

        if ($this->_errorCode === Crypt_GPG::ERROR_NONE) {
            $pattern = '/secret key not available/';
            if (preg_match($pattern, $line) === 1) {
                $this->_errorCode = Crypt_GPG::ERROR_KEY_NOT_FOUND;
            }
        }

        if ($this->_errorCode === Crypt_GPG::ERROR_NONE) {
            $pattern = '/public key not found/';
            if (preg_match($pattern, $line) === 1) {
                $this->_errorCode = Crypt_GPG::ERROR_KEY_NOT_FOUND;
            }
        }
    }

    // }}}
    // {{{ _handleDebugStatus()

    /**
     * Displays debug output for status lines
     *
     * @param string $line the status line to handle.
     *
     * @return void
     */
    private function _handleDebugStatus($line)
    {
        $this->_debug('STATUS: ' . $line);
    }

    // }}}
    // {{{ _handleDebugError()

    /**
     * Displays debug output for error lines
     *
     * @param string $line the error line to handle.
     *
     * @return void
     */
    private function _handleDebugError($line)
    {
        $this->_debug('ERROR: ' . $line);
    }

    // }}}
    // {{{ _process()

    /**
     * Performs internal streaming operations for the subprocess using either
     * strings or streams as input / output points
     *
     * This is the main I/O loop for streaming to and from the GPG subprocess.
     *
     * The implementation of this method is verbose mainly for performance
     * reasons. Adding streams to a lookup array and looping the array inside
     * the main I/O loop would be siginficantly slower for large streams.
     *
     * @return void
     */
    private function _process()
    {
        $this->_debug('BEGIN PROCESSING');

        $this->_commandBuffer = '';    // buffers input to GPG
        $messageBuffer        = '';    // buffers input to GPG
        $inputBuffer          = '';    // buffers input to GPG
        $outputBuffer         = '';    // buffers output from GPG
        $statusBuffer         = '';    // buffers output from GPG
        $errorBuffer          = '';    // buffers output from GPG
        $inputComplete        = false; // input stream is completely buffered
        $messageComplete      = false; // message stream is completely buffered

        if (is_string($this->_input)) {
            $inputBuffer   = $this->_input;
            $inputComplete = true;
        }

        if (is_string($this->_message)) {
            $messageBuffer   = $this->_message;
            $messageComplete = true;
        }

        if (is_string($this->_output)) {
            $outputBuffer =& $this->_output;
        }

        // convenience variables
        $fdInput   = $this->_pipes[self::FD_INPUT];
        $fdOutput  = $this->_pipes[self::FD_OUTPUT];
        $fdError   = $this->_pipes[self::FD_ERROR];
        $fdStatus  = $this->_pipes[self::FD_STATUS];
        $fdCommand = $this->_pipes[self::FD_COMMAND];
        $fdMessage = $this->_pipes[self::FD_MESSAGE];

        while (true) {

            $inputStreams     = array();
            $outputStreams    = array();
            $exceptionStreams = array();

            // set up input streams
            if (is_resource($this->_input) && !$inputComplete) {
                if (feof($this->_input)) {
                    $inputComplete = true;
                } else {
                    $inputStreams[] = $this->_input;
                }
            }

            if (is_resource($this->_message) && !$messageComplete) {
                if (feof($this->_message)) {
                    $messageComplete = true;
                } else {
                    $inputStreams[] = $this->_message;
                }
            }

            if (!feof($fdOutput)) {
                $inputStreams[] = $fdOutput;
            }

            if (!feof($fdStatus)) {
                $inputStreams[] = $fdStatus;
            }

            if (!feof($fdError)) {
                $inputStreams[] = $fdError;
            }

            // set up output streams
            if ($outputBuffer != '' && is_resource($this->_output)) {
                $outputStreams[] = $this->_output;
            }

            if ($this->_commandBuffer != '') {
                $outputStreams[] = $fdCommand;
            }

            if ($messageBuffer != '') {
                $outputStreams[] = $fdMessage;
            }

            if ($inputBuffer != '') {
                $outputStreams[] = $fdInput;
            }

            // no streams left to read or write, we're all done
            if (count($inputStreams) === 0 && count($outputStreams) === 0) {
                break;
            }

            $this->_debug('selecting streams');

            $ready = stream_select($inputStreams, $outputStreams,
                $exceptionStreams, null);

            $this->_debug('=> got ' . $ready);

            if ($ready === false) {
                throw new Crypt_GPG_Exception(
                    'Error selecting stream for communication with GPG ' .
                        'subprocess.');
            }

            if ($ready === 0) {
                throw new Crypt_GPG_Exception(
                    'stream_select() returned 0. This can not happen!');
            }

            // write input (to GPG)
            if (in_array($fdInput, $outputStreams)) {
                $this->_debug('GPG is ready for input');

                $chunk = self::_byteSubstring($inputBuffer,
                    0, self::CHUNK_SIZE);

                $length = self::_byteLength($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes ' .
                    'to GPG input');

                $length = fwrite($fdInput, $chunk, $length);

                $this->_debug('=> wrote ' . $length . ' bytes');

                $inputBuffer = self::_byteSubstring($inputBuffer,
                    $length);

                // close GPG input pipe if there is no more data
                if ($inputBuffer == '' && $inputComplete) {
                    $this->_debug('=> closing GPG input pipe');
                    $this->_closePipe(self::FD_INPUT);
                }
            }

            // read input (from PHP stream)
            if (in_array($this->_input, $inputStreams)) {
                $this->_debug('input stream is ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE .
                    'bytes from input stream');

                $chunk = fread($this->_input, self::CHUNK_SIZE);
                $length = self::_byteLength($chunk);
                $inputBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');
            }

            // write message (to GPG)
            if (in_array($fdMessage, $outputStreams)) {
                $this->_debug('GPG is ready for message data');

                $chunk = self::_byteSubstring($messageBuffer,
                    0, self::CHUNK_SIZE);

                $length = self::_byteLength($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes ' .
                    'to GPG message');

                $length = fwrite($fdMessage, $chunk, $length);
                $this->_debug('=> wrote ' . $length . ' bytes');

                $messageBuffer = self::_byteSubstring($messageBuffer, $length);

                // close GPG message pipe if there is no more data
                if ($messageBuffer == '' && $messageComplete) {
                    $this->_debug('=> closing GPG message pipe');
                    $this->_closePipe(self::FD_MESSAGE);
                }
            }

            // read message (from PHP stream)
            if (in_array($this->_message, $inputStreams)) {
                $this->_debug('message stream is ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE .
                    ' bytes from message stream');

                $chunk = fread($this->_message, self::CHUNK_SIZE);
                $length = self::_byteLength($chunk);
                $messageBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');
            }

            // read output (from GPG)
            if (in_array($fdOutput, $inputStreams)) {
                $this->_debug('GPG output stream ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE .
                    ' bytes from GPG output');

                $chunk = fread($fdOutput, self::CHUNK_SIZE);
                $length = self::_byteLength($chunk);
                $outputBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');
            }

            // write output (to PHP stream)
            if (in_array($this->_output, $outputStreams)) {
                $this->_debug('output stream is ready for data');

                $chunk = self::_byteSubstring($outputBuffer,
                    0, self::CHUNK_SIZE);

                $length = self::_byteLength($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes ' .
                    'to output stream');

                $length = fwrite($this->_output, $chunk, $length);

                $this->_debug('=> wrote ' . $length . ' bytes');

                $outputBuffer = self::_byteSubstring($outputBuffer, $length);
            }

            // read error (from GPG)
            if (in_array($fdError, $inputStreams)) {
                $this->_debug('GPG error stream ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE .
                    ' bytes from GPG error');

                $chunk = fread($fdError, self::CHUNK_SIZE);
                $length = self::_byteLength($chunk);
                $errorBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');

                // pass lines to error handlers
                while (($pos = strpos($errorBuffer, PHP_EOL)) !== false) {
                    $line = self::_byteSubstring($errorBuffer, 0, $pos);
                    foreach ($this->_errorHandlers as $handler) {
                        array_unshift($handler['args'], $line);
                        call_user_func_array($handler['callback'],
                            $handler['args']);

                        array_shift($handler['args']);
                    }
                    $errorBuffer = self::_byteSubString($errorBuffer,
                        $pos + self::_byteLength(PHP_EOL));
                }
            }

            // read status (from GPG)
            if (in_array($fdStatus, $inputStreams)) {
                $this->_debug('GPG status stream ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE .
                    ' bytes from GPG status');

                $chunk = fread($fdStatus, self::CHUNK_SIZE);
                $length = self::_byteLength($chunk);
                $statusBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');

                // pass lines to status handlers
                while (($pos = strpos($statusBuffer, PHP_EOL)) !== false) {
                    $line = self::_byteSubstring($statusBuffer, 0, $pos);
                    // only pass lines beginning with magic prefix
                    if (self::_byteSubstring($line, 0, 9) == '[GNUPG:] ') {
                        $line = self::_byteSubstring($line, 9);
                        foreach ($this->_statusHandlers as $handler) {
                            array_unshift($handler['args'], $line);
                            call_user_func_array($handler['callback'],
                                $handler['args']);

                            array_shift($handler['args']);
                        }
                    }
                    $statusBuffer = self::_byteSubString($statusBuffer,
                        $pos + self::_byteLength(PHP_EOL));
                }
            }

            // write command (to GPG)
            if (in_array($fdCommand, $outputStreams)) {
                $this->_debug('GPG is ready for command data');

                // send commands
                $chunk = self::_byteSubstring($this->_commandBuffer,
                    0, self::CHUNK_SIZE);

                $length = self::_byteLength($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes ' .
                    'to GPG command');

                $length = fwrite($fdCommand, $chunk, $length);

                $this->_debug('=> wrote ' . $length);

                $this->_commandBuffer =
                    self::_byteSubstring($this->_commandBuffer, $length);
            }

        } // end loop while streams are open

        $this->_debug('END PROCESSING');
    }

    // }}}
    // {{{ _openSubprocess()

    /**
     * Opens an internal GPG subprocess for the current operation
     *
     * Opens a GPG subprocess, then connects the subprocess to some pipes. Sets
     * the private class property {@link Crypt_GPG_Engine::$_process} to
     * the new subprocess.
     *
     * @param array $env optional. An array of shell environment variables.
     *                   Defaults to <code>$_ENV</code> if not specified.
     *
     * @return void
     *
     * @throws Crypt_GPG_OpenSubprocessException if the subprocess could not be
     *         opened.
     *
     * @see Crypt_GPG_Engine::setOperation()
     * @see Crypt_GPG_Engine::_closeSubprocess()
     * @see Crypt_GPG_Engine::$_process
     */
    private function _openSubprocess(array $env = null)
    {
        if ($env === null) {
            $env = $_ENV;
        }

        $commandLine = $this->_gpgBinary;

        $arguments = array_merge(array(
            '--status-fd ' . escapeshellarg(self::FD_STATUS),
            '--command-fd ' . escapeshellarg(self::FD_COMMAND),
            '--no-use-agent',
            '--no-secmem-warning',
            '--no-permission-warning',
            '--no-tty',
            '--exit-on-status-write-error',
            '--trust-model always'
        ), $this->_arguments);

        if ($this->_homedir) {
            $arguments[] = '--homedir ' . escapeshellarg($this->_homedir);
        }

        $commandLine .= ' ' . implode(' ', $arguments) . ' ' .
            $this->_operation;

        // Binary operations will not work on Windows with PHP < 5.2.6. This is
        // in case stream_select() ever works on Windows.
        $rb = (version_compare(PHP_VERSION, '5.2.6') < 0) ? 'r' : 'rb';
        $wb = (version_compare(PHP_VERSION, '5.2.6') < 0) ? 'w' : 'wb';

        $descriptorSpec = array(
            self::FD_INPUT   => array('pipe', $rb), // stdin
            self::FD_OUTPUT  => array('pipe', $wb), // stdout
            self::FD_ERROR   => array('pipe', $wb), // stderr
            self::FD_STATUS  => array('pipe', $wb), // status
            self::FD_COMMAND => array('pipe', $rb), // command
            self::FD_MESSAGE => array('pipe', $rb)  // message
        );

        $this->_debug('OPENING SUBPROCESS WITH THE FOLLOWING COMMAND:');
        $this->_debug($commandLine);

        $this->_process = proc_open($commandLine, $descriptorSpec,
            $this->_pipes, null, $env, array('binary_pipes' => true));

        if (!is_resource($this->_process)) {
            throw new Crypt_GPG_OpenSubprocessException(
                'Unable to open GPG subprocess.', 0, $command);
        }

        $this->_openPipes = $this->_pipes;
        $this->_errorCode = Crypt_GPG::ERROR_NONE;
    }

    // }}}
    // {{{ _closeSubprocess()

    /**
     * Closes a the internal GPG subprocess
     *
     * Closes the internal GPG subprocess. Sets the private class property
     * {@link Crypt_GPG_Engine::$_process} to null.
     *
     * @return void
     *
     * @see Crypt_GPG_Engine::_openSubprocess()
     * @see Crypt_GPG_Engine::$_process
     */
    private function _closeSubprocess()
    {
        if (is_resource($this->_process)) {
            $this->_debug('CLOSING SUBPROCESS');

            // close remaining open pipes
            foreach (array_keys($this->_openPipes) as $pipeNumber) {
                $this->_closePipe($pipeNumber);
            }

            $exitCode = proc_close($this->_process);

            if ($exitCode != 0) {
                $this->_debug('=> subprocess returned an unexpected exit ' .
                    'code: ' . $exitCode);

                // $this->_debug("Error text is:\n" . $error);
                // $this->_debug("Status text is:\n" . $status);

                if ($this->_errorCode === Crypt_GPG::ERROR_NONE) {
                    if ($this->_needPassphrase > 0) {
                        $this->_errorCode = Crypt_GPG::ERROR_MISSING_PASSPHRASE;
                    } else {
                        $this->_errorCode = Crypt_GPG::ERROR_UNKNOWN;
                    }
                }
            }

            $this->_process = null;
            $this->_pipes   = array();
        }
    }

    // }}}
    // {{{ _closePipe()

    /**
     * Closes an opened pipe used to communicate with the GPG subprocess
     *
     * If the pipe is already closed, it is ignored. If the pipe is open, it
     * is flushed and then closed.
     *
     * @param integer $pipeNumber the file descriptor number of the pipe to
     *                            close.
     *
     * @return void
     */
    private function _closePipe($pipeNumber)
    {
        $pipeNumber = intval($pipeNumber);
        if (array_key_exists($pipeNumber, $this->_openPipes)) {
            fflush($this->_openPipes[$pipeNumber]);
            fclose($this->_openPipes[$pipeNumber]);
            unset($this->_openPipes[$pipeNumber]);
        }
    }

    // }}}
    // {{{ _getBinary()

    /**
     * Gets the name of the GPG binary for the current operating system
     *
     * This method is called if the 'gpgBinary' option is <i>not</i> specified
     * when creating this driver.
     *
     * @return string the name of the GPG binary for the current operating
     *                system. If no suitable binary could be found, an empty
     *                string is returned.
     */
    private function _getBinary()
    {
        $binary = '';

        if ($this->_isDarwin) {
            $binaryFiles = array(
                '/opt/local/bin/gpg', // MacPorts
                '/usr/local/bin/gpg', // Mac GPG
                '/sw/bin/gpg',        // Fink
                '/usr/bin/gpg'
            );
        } else {
            $binaryFiles = array(
                '/usr/bin/gpg',
                '/usr/local/bin/gpg'
            );
        }

        foreach ($binaryFiles as $binaryFile) {
            if (is_executable($binaryFile)) {
                $binary = $binaryFile;
                break;
            }
        }

        return $binary;
    }

    // }}}
    // {{{ _debug()

    /**
     * Displays debug text if debugging is turned on
     *
     * Debugging text is prepended with a debug identifier and echoed to stdout.
     *
     * @param string $text the debugging text to display.
     *
     * @return void
     */
    private function _debug($text)
    {
        if ($this->_debug) {
            if (array_key_exists('SHELL', $_ENV)) {
                foreach (explode(PHP_EOL, $text) as $line) {
                    echo "Crypt_GPG DEBUG: ", $line, PHP_EOL;
                }
            } else {
                // running on a web server, format debug output nicely
                foreach (explode(PHP_EOL, $text) as $line) {
                    echo "Crypt_GPG DEBUG: <strong>", $line,
                        '</strong><br />', PHP_EOL;
                }
            }
        }
    }

    // }}}
    // {{{ _byteLength()

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
     * @see Crypt_GPG_Engine::$_mbStringOverload
     */
    private static function _byteLength($string)
    {
        if (self::$_mbStringOverload) {
            return mb_strlen($string, '8bit');
        }

        return strlen((binary)$string);
    }

    // }}}
    // {{{ _byteSubstring()

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
     *                <code>substr()</code> function, the returned value is
     *                always a string and never false.
     *
     * @see Crypt_GPG_Engine::$_mbStringOverload
     */
    private static function _byteSubstring($string, $start, $length = null)
    {
        if (self::$_mbStringOverload) {
            if ($length === null) {
                return mb_substr($string, $start,
                    self::_byteLength($string) - $start, '8bit');
            }

            return mb_substr($string, $start, $length, '8bit');
        }

        if ($length === null) {
            return (string)substr((binary)$string, $start);
        }

        return (string)substr((binary)$string, $start, $length);
    }

    // }}}
}

// }}}

?>
