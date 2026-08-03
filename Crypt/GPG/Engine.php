<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

namespace Crypt\GPG;

use Crypt\GPG;
use Crypt\GPG\Exceptions;
use Crypt\GPG\KeyEditor;
use Crypt\GPG\ProcessHandler;
use Crypt\GPG\SignatureCreationInfo;

/**
 * Native PHP Crypt_GPG I/O engine
 *
 * This class is used internally by Crypt_GPG and does not need be used
 * directly. See the {@link Crypt\GPG} class for end-user API.
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
 * @copyright 2005-2013 silverorange
 * @license   https://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      https://github.com/pear/Crypt_GPG
 */
class Engine
{
    /**
     * Size of data chunks that are sent to and retrieved from the IPC pipes.
     *
     * The value of 65536 has been chosen empirically
     * as the one with best performance.
     *
     * @see https://pear.php.net/bugs/bug.php?id=21077
     */
    public const CHUNK_SIZE = 65536;

    /**
     * Standard input file descriptor. This is used to pass data to the GPG
     * process.
     */
    public const FD_INPUT = 0;

    /**
     * Standard output file descriptor. This is used to receive normal output
     * from the GPG process.
     */
    public const FD_OUTPUT = 1;

    /**
     * Standard output file descriptor. This is used to receive error output
     * from the GPG process.
     */
    public const FD_ERROR = 2;

    /**
     * GPG status output file descriptor. The status file descriptor outputs
     * detailed information for many GPG commands. See the second section of
     * the file <b>doc/DETAILS</b> in the
     * {@link http://www.gnupg.org/download/ GPG package} for a detailed
     * description of GPG's status output.
     */
    public const FD_STATUS = 3;

    /**
     * Command input file descriptor. This is used for methods requiring
     * passphrases.
     */
    public const FD_COMMAND = 4;

    /**
     * Extra message input file descriptor. This is used for passing signed
     * data when verifying a detached signature.
     */
    public const FD_MESSAGE = 5;

    /**
     * Minimum version of GnuPG that is supported.
     */
    public const MIN_VERSION = '2.2.0';

    /**
     * Whether or not to use strict mode
     *
     * When set to true, any clock problems (e.g. keys generate in future)
     * are errors, otherwise they are just warnings.
     *
     * Strict mode is disabled by default.
     *
     * @var bool
     * @see self::__construct()
     */
    private $_strict = false;

    /**
     * Whether or not to use debugging mode
     *
     * When set to true, every GPG command is echoed before it is run. Sensitive
     * data is always handled using pipes and is not specified as part of the
     * command. As a result, sensitive data is never displayed when debug is
     * enabled. Sensitive data includes private key data and passphrases.
     *
     * This can be set to a callable function where first argument is the
     * debug line to process.
     *
     * @var bool|callable
     * @see self::__construct()
     */
    private $_debug = false;

    /**
     * Location of GPG binary
     *
     * @var string
     * @see self::__construct()
     * @see self::_getBinary()
     */
    private $_binary = '';

    /**
     * Directory containing the GPG key files
     *
     * This property only contains the path when the <i>homedir</i> option
     * is specified in the constructor.
     *
     * @var string
     * @see self::__construct()
     */
    private $_homedir = '';

    /**
     * File path of the public keyring
     *
     * This property only contains the file path when the <i>public_keyring</i>
     * option is specified in the constructor.
     *
     * If the specified file path starts with <kbd>~/</kbd>, the path is
     * relative to the <i>homedir</i> if specified, otherwise to
     * <kbd>~/.gnupg</kbd>.
     *
     * @var string
     * @see self::__construct()
     */
    private $_publicKeyring = '';

    /**
     * File path of the private (secret) keyring
     *
     * This property only contains the file path when the <i>private_keyring</i>
     * option is specified in the constructor.
     *
     * If the specified file path starts with <kbd>~/</kbd>, the path is
     * relative to the <i>homedir</i> if specified, otherwise to
     * <kbd>~/.gnupg</kbd>.
     *
     * @var string
     * @see self::__construct()
     */
    private $_privateKeyring = '';

    /**
     * File path of the trust database
     *
     * This property only contains the file path when the <i>trust_db</i>
     * option is specified in the constructor.
     *
     * If the specified file path starts with <kbd>~/</kbd>, the path is
     * relative to the <i>homedir</i> if specified, otherwise to
     * <kbd>~/.gnupg</kbd>.
     *
     * @var string
     * @see self::__construct()
     */
    private $_trustDb = '';

    /**
     * Array of pipes used for communication with the GPG binary
     *
     * This is an array of file descriptor resources.
     *
     * @var array
     */
    private $_pipes = [];

    /**
     * Array of currently opened pipes
     *
     * This array is used to keep track of remaining opened pipes so they can
     * be closed when the GPG subprocess is finished. This array is a subset of
     * the {@link \Crypt\GPG\Engine::$_pipes} array and contains opened file
     * descriptor resources.
     *
     * @var array
     * @see self::_closePipe()
     */
    private $_openPipes = [];

    /**
     * A handle for the GPG process
     *
     * @var resource|null
     */
    private $_process = null;

    /**
     * Whether or not the operating system is Darwin (OS X)
     *
     * @var bool
     */
    private $_isDarwin = false;

    /**
     * Message digest algorithm.
     *
     * @var string
     */
    private $_digest_algo = null;

    /**
     * Symmetric cipher algorithm.
     *
     * @var string
     */
    private $_cipher_algo = null;

    /**
     * Compress algorithm.
     *
     * @var string
     */
    private $_compress_algo = null;

    /**
     * Additional per-command arguments
     *
     * @var array
     */
    private $_options = [];

    /**
     * Commands to be sent to GPG's command input stream
     *
     * @var string
     * @see self::sendCommand()
     */
    private $_commandBuffer = '';

    /**
     * A status/error handler
     *
     * @var ProcessHandler|null
     */
    private $_processHandler = null;

    /**
     * Array of status line handlers
     *
     * @var array
     * @see self::addStatusHandler()
     */
    private $_statusHandlers = [];

    /**
     * Array of error line handlers
     *
     * @var array
     * @see self::addErrorHandler()
     */
    private $_errorHandlers = [];

    /**
     * The input source
     *
     * This is data to send to GPG. Either a string or a stream resource.
     *
     * @var string|resource|null
     * @see self::setInput()
     */
    private $_input = null;

    /**
     * The extra message input source
     *
     * Either a string or a stream resource.
     *
     * @var string|resource|null
     * @see self::setMessage()
     */
    private $_message = null;

    /**
     * The output location
     *
     * This is where the output from GPG is sent. Either a string or a stream resource.
     *
     * @var string|resource
     * @see self::setOutput()
     */
    private $_output = '';

    /**
     * The GPG operation to execute
     *
     * @var string
     * @see self::setOperation()
     */
    private $_operation;

    /**
     * Arguments for the current operation
     *
     * @var array
     * @see self::setOperation()
     */
    private $_arguments = [];

    /**
     * The version number of the GPG binary
     *
     * @var string
     * @see self::getVersion()
     */
    private $_version = '';

    /**
     * Creates a new GPG engine
     *
     * @param array $options An array of options used to create the engine object.
     *                       All options are optional and are represented as key-value
     *                       pairs. See {@link Crypt\GPG::__construct()} for more info.
     *
     * @throws Exceptions\FileException if the <kbd>homedir</kbd> does not exist
     *         and cannot be created. This can happen if <kbd>homedir</kbd> is
     *         not specified, Crypt_GPG is run as the web user, and the web
     *         user has no home directory. This exception is also thrown if any
     *         of the options <kbd>publicKeyring</kbd>,
     *         <kbd>privateKeyring</kbd> or <kbd>trustDb</kbd> options are
     *         specified but the files do not exist or are are not readable.
     *         This can happen if the user running the Crypt_GPG process (for
     *         example, the Apache user) does not have permission to read the
     *         files.
     *
     * @throws Exceptions\Exception if the provided <kbd>binary</kbd> is invalid, or
     *         if no <kbd>binary</kbd> is provided and no suitable binary could
     *         be found.
     */
    public function __construct(array $options = [])
    {
        $this->_isDarwin = (strncmp(strtoupper(PHP_OS), 'DARWIN', 6) === 0);

        // get homedir
        if (array_key_exists('homedir', $options)) {
            $this->_homedir = (string) $options['homedir'];
        } else {
            if (extension_loaded('posix')) {
                // note: this requires the package OS dep exclude 'windows'
                $info = posix_getpwuid(posix_getuid());
                $this->_homedir = $info['dir'] . '/.gnupg';
            } else {
                if (isset($_SERVER['HOME'])) {
                    $this->_homedir = $_SERVER['HOME'];
                } else {
                    $this->_homedir = getenv('HOME');
                }
            }

            if ($this->_homedir === false) {
                throw new Exceptions\FileException(
                    'Could not locate homedir. Please specify the homedir '
                    . 'to use with the \'homedir\' option when instantiating '
                    . 'the Crypt\\GPG object.'
                );
            }
        }

        // attempt to create homedir if it does not exist
        if (!is_dir($this->_homedir)) {
            if (@mkdir($this->_homedir, 0o777, true)) {
                // Set permissions on homedir. Parent directories are created
                // with 0777, homedir is set to 0700.
                chmod($this->_homedir, 0o700);
            } else {
                throw new Exceptions\FileException(
                    'The \'homedir\' "' . $this->_homedir . '" is not '
                    . 'readable or does not exist and cannot be created. This '
                    . 'can happen if \'homedir\' is not specified in the '
                    . 'Crypt\\GPG options, Crypt_GPG is run as the web user, '
                    . 'and the web user has no home directory.',
                    0,
                    $this->_homedir
                );
            }
        }

        // check homedir permissions (See Bug #19833)
        if (!is_executable($this->_homedir)) {
            throw new Exceptions\FileException(
                'The \'homedir\' "' . $this->_homedir . '" is not enterable '
                . 'by the current user. Please check the permissions on your '
                . 'homedir and make sure the current user can both enter and '
                . 'write to the directory.',
                0,
                $this->_homedir
            );
        }
        if (!is_writeable($this->_homedir)) {
            throw new Exceptions\FileException(
                'The \'homedir\' "' . $this->_homedir . '" is not writable '
                . 'by the current user. Please check the permissions on your '
                . 'homedir and make sure the current user can both enter and '
                . 'write to the directory.',
                0,
                $this->_homedir
            );
        }

        // get binary
        if (array_key_exists('binary', $options)) {
            $this->_binary = (string) $options['binary'];
        } elseif (array_key_exists('gpgBinary', $options)) {
            // deprecated alias
            $this->_binary = (string) $options['gpgBinary'];
        } else {
            $this->_binary = $this->_getBinary();
        }

        if ($this->_binary == '' || !is_executable($this->_binary)) {
            throw new Exceptions\Exception(
                'GPG binary not found. If you are sure the GPG binary is '
                . 'installed, please specify the location of the GPG binary '
                . 'using the \'binary\' driver option.'
            );
        }

        /*
         * Note:
         *
         * Normally, GnuPG expects keyrings to be in the homedir and expects
         * to be able to write temporary files in the homedir. Sometimes,
         * keyrings are not in the homedir, or location of the keyrings does
         * not allow writing temporary files. In this case, the <i>homedir</i>
         * option by itself is not enough to specify the keyrings because GnuPG
         * can not write required temporary files. Additional options are
         * provided so you can specify the location of the keyrings separately
         * from the homedir.
         */

        // get public keyring
        if (array_key_exists('publicKeyring', $options)) {
            $this->_publicKeyring = (string) $options['publicKeyring'];
            if (!is_readable($this->_publicKeyring)) {
                throw new Exceptions\FileException(
                    'The \'publicKeyring\' "' . $this->_publicKeyring
                    . '" does not exist or is not readable. Check the location '
                    . 'and ensure the file permissions are correct.',
                    0,
                    $this->_publicKeyring
                );
            }
        }

        // get private keyring
        if (array_key_exists('privateKeyring', $options)) {
            $this->_privateKeyring = (string) $options['privateKeyring'];
            if (!is_readable($this->_privateKeyring)) {
                throw new Exceptions\FileException(
                    'The \'privateKeyring\' "' . $this->_privateKeyring
                    . '" does not exist or is not readable. Check the location '
                    . 'and ensure the file permissions are correct.',
                    0,
                    $this->_privateKeyring
                );
            }
        }

        // get trust database
        if (array_key_exists('trustDb', $options)) {
            $this->_trustDb = (string) $options['trustDb'];
            if (!is_readable($this->_trustDb)) {
                throw new Exceptions\FileException(
                    'The \'trustDb\' "' . $this->_trustDb
                    . '" does not exist or is not readable. Check the location '
                    . 'and ensure the file permissions are correct.',
                    0,
                    $this->_trustDb
                );
            }
        }

        if (array_key_exists('debug', $options)) {
            $this->_debug = $options['debug'];
        }

        $this->_strict = !empty($options['strict']);

        if (!empty($options['digest-algo'])) {
            $this->_digest_algo = $options['digest-algo'];
        }

        if (!empty($options['cipher-algo'])) {
            $this->_cipher_algo = $options['cipher-algo'];
        }

        if (!empty($options['compress-algo'])) {
            $this->_compress_algo = $options['compress-algo'];
        }

        if (!empty($options['options'])) {
            $this->_options = $options['options'];
        }
    }

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

    /**
     * Adds an error handler method
     *
     * The method is run every time a new error line is received from the GPG
     * subprocess. The handler method must accept the error line to be handled
     * as its first parameter.
     *
     * @param callable $callback the callback method to use.
     * @param array    $args     optional. Additional arguments to pass as
     *                           parameters to the callback method.
     */
    public function addErrorHandler($callback, array $args = []): void
    {
        $this->_errorHandlers[] = [
            'callback' => $callback,
            'args'     => $args,
        ];
    }

    /**
     * Adds a status handler method
     *
     * The method is run every time a new status line is received from the
     * GPG subprocess. The handler method must accept the status line to be
     * handled as its first parameter.
     *
     * @param callable $callback the callback method to use.
     * @param array    $args     optional. Additional arguments to pass as
     *                           parameters to the callback method.
     */
    public function addStatusHandler($callback, array $args = []): void
    {
        $this->_statusHandlers[] = [
            'callback' => $callback,
            'args'     => $args,
        ];
    }

    /**
     * Sends a command to the GPG subprocess over the command file-descriptor
     * pipe
     *
     * @param string $command the command to send.
     *
     * @sensitive $command
     */
    public function sendCommand($command): void
    {
        if (array_key_exists(self::FD_COMMAND, $this->_openPipes)) {
            $this->_commandBuffer .= $command . PHP_EOL;
        }
    }

    /**
     * Resets the GPG engine, preparing it for a new operation
     *
     * @see self::run()
     * @see self::setOperation()
     */
    public function reset(): void
    {
        $this->_operation      = '';
        $this->_arguments      = [];
        $this->_input          = null;
        $this->_message        = null;
        $this->_output         = '';
        $this->_commandBuffer  = '';

        $this->_statusHandlers = [];
        $this->_errorHandlers  = [];

        if ($this->_debug) {
            $this->addStatusHandler([$this, '_handleDebugStatus']);
            $this->addErrorHandler([$this, '_handleDebugError']);
        }

        $this->_processHandler = new ProcessHandler($this);

        $this->addStatusHandler([$this->_processHandler, 'handleStatus']);
        $this->addErrorHandler([$this->_processHandler, 'handleError']);
    }

    /**
     * Runs the current GPG operation.
     *
     * This creates and manages the GPG subprocess.
     * This will close input/output file handles.
     *
     * The operation must be set with {@link Crypt\GPG\Engine::setOperation()}
     * before this method is called.
     *
     * @throws Exceptions\InvalidOperationException if no operation is specified.
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *
     * @see self::reset()
     * @see self::setOperation()
     */
    public function run(): void
    {
        if ($this->_operation === '') {
            throw new Exceptions\InvalidOperationException(
                'No GPG operation specified. Use Crypt\\GPG\\Engine::setOperation() '
                . 'before calling Crypt\\GPG\\Engine::run().'
            );
        }

        $this->_openSubprocess();
        $this->_process();
        $this->_closeSubprocess();
    }

    /**
     * Sets the input source for the current GPG operation
     *
     * @param string|resource &$input Either a reference to the string
     *                                containing the input data or an open
     *                                stream resource containing the input data
     */
    public function setInput(&$input): void
    {
        $this->_input = & $input;
    }

    /**
     * Sets the message source for the current GPG operation
     *
     * Detached signature data should be specified here.
     *
     * @param string|resource &$message Either a reference to the string
     *                                  containing the message data or an open
     *                                  stream resource containing the message data
     */
    public function setMessage(&$message): void
    {
        $this->_message = & $message;
    }

    /**
     * Sets the output destination for the current GPG operation
     *
     * @param string|resource &$output Either a reference to the string in
     *                                 which to store GPG output or an open
     *                                 stream resource to which the output data
     *                                 should be written
     */
    public function setOutput(&$output): void
    {
        $this->_output = & $output;
    }

    /**
     * Sets the operation to perform
     *
     * @param string $operation the operation to perform. This should be one
     *                          of GPG's operations. For example,
     *                          <kbd>--encrypt</kbd>, <kbd>--decrypt</kbd>,
     *                          <kbd>--sign</kbd>, etc.
     * @param array  $arguments optional. Additional arguments for the GPG
     *                          subprocess. See the GPG manual for specific
     *                          values.
     *
     * @see self::reset()
     * @see self::run()
     */
    public function setOperation($operation, array $arguments = []): void
    {
        $this->_operation = $operation;
        $this->_arguments = $arguments;

        foreach ($this->_options as $optname => $args) {
            if (str_contains($operation, '--' . $optname)) {
                $this->_arguments[] = $args;
            }
        }

        $this->_processHandler->setOperation($operation);
    }

    /**
     * Sets the PINENTRY_USER_DATA environment variable with the currently
     * added keys and passphrases
     *
     * Keys and passphrases are stored as an indexed array of passphrases
     * in JSON encoded to a flat string.
     *
     * For GnuPG 2.x this is how passphrases are passed.
     *
     * @param array $keys the internal key array to use.
     */
    public function setPins(array $keys): void
    {
        $envKeys = [];

        foreach ($keys as $keyId => $key) {
            $envKeys[$keyId] = is_array($key) ? $key['passphrase'] : $key;
        }

        $_ENV['PINENTRY_USER_DATA'] = json_encode($envKeys);
    }

    /**
     * Sets per-command additional arguments
     *
     * @param array $options Additional per-command options for GPG command.
     *                       Note: This will unset options set previously.
     *                       Key of the array is a command (e.g.
     *                       gen-key, import, sign, encrypt, list-keys).
     *                       Value is a string containing command line arguments to be
     *                       added to the related command. For example:
     *                       ['sign' => '--emit-version'].
     */
    public function setOptions(array $options): void
    {
        $this->_options = $options;
    }

    /**
     * Gets the version of the GnuPG binary
     *
     * @return string a version number string containing the version of GnuPG
     *                being used. This value is suitable to use with PHP's
     *                version_compare() function.
     *
     * @throws Exceptions\Exception if an unknown or unexpected error occurs.
     *         Use the <kbd>debug</kbd> option and file a bug report if these
     *         exceptions occur.
     *
     * @throws Exceptions\Exception if the provided binary is not
     *         GnuPG or if the GnuPG version is less than {@link self::MIN_VERSION }
     */
    public function getVersion(): string
    {
        if ($this->_version == '') {
            $options = [
                'homedir' => $this->_homedir,
                'binary'  => $this->_binary,
                'debug'   => $this->_debug,
            ];

            $engine = new self($options);
            $info   = '';

            // Set a garbage version so we do not end up looking up the version
            // recursively.
            $engine->_version = '1.0.0';

            $engine->reset();
            $engine->setOutput($info);
            $engine->setOperation('--version');
            $engine->run();

            $matches    = [];
            $expression = '#gpg \(GnuPG[A-Za-z0-9/]*?\) (\S+)#';

            if (preg_match($expression, $info, $matches) === 1) {
                $this->_version = $matches[1];
            } else {
                throw new Exceptions\Exception(
                    'No GnuPG version information provided by the binary "'
                    . $this->_binary . '". Are you sure it is GnuPG?'
                );
            }

            if (version_compare($this->_version, self::MIN_VERSION, 'lt')) {
                throw new Exceptions\Exception(
                    'The version of GnuPG being used (' . $this->_version
                    . ') is not supported by Crypt_GPG. The minimum version '
                    . 'required by Crypt_GPG is ' . self::MIN_VERSION
                );
            }
        }

        return $this->_version;
    }

    /**
     * Get data from the last process execution.
     *
     * @param string $name Data element name (e.g. 'SignatureInfo')
     *
     * @return mixed
     * @see    \Crypt\GPG\ProcessHandler::getData()
     */
    public function getProcessData($name)
    {
        if ($this->_processHandler) {
            switch ($name) {
                case 'SignatureInfo':
                    if ($data = $this->_processHandler->getData('SigCreated')) {
                        return new SignatureCreationInfo($data);
                    }
                    break;

                case 'Signatures':
                case 'Warnings':
                    return (array) $this->_processHandler->getData($name);

                default:
                    return $this->_processHandler->getData($name);
            }
        }
    }

    /**
     * Set some data for the process execution.
     *
     * @param string $name  Data element name (e.g. 'Handle')
     * @param mixed  $value Data value
     */
    public function setProcessData($name, $value): void
    {
        if ($this->_processHandler) {
            $this->_processHandler->setData($name, $value);
        }
    }

    /**
     * Initialize key editor instance
     */
    public function getKeyEditor(): KeyEditor
    {
        $keys = ['homedir', 'binary', 'publicKeyring', 'privateKeyring', 'trustDb'];
        $options = [];

        foreach ($keys as $key) {
            if (isset($this->{"_{$key}"})) {
                $options[$key] = $this->{"_{$key}"};
            }
        }

        if ($this->_debug) {
            $options['debug'] = function ($line) {
                $this->_debug($line);
            };
        }

        return new KeyEditor($this, $options);
    }

    /**
     * Displays debug output for status lines
     *
     * @param string $line the status line to handle.
     */
    private function _handleDebugStatus($line): void
    {
        $this->_debug('STATUS: ' . $line);
    }

    /**
     * Displays debug output for error lines
     *
     * @param string $line the error line to handle.
     */
    private function _handleDebugError($line): void
    {
        $this->_debug('ERROR: ' . $line);
    }

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
     * @throws Exceptions\Exception if there is an error selecting streams for
     *         reading or writing. If this occurs, please file a bug report at
     *         https://github.com/pear/Crypt_GPG/issues
     */
    private function _process(): void
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
            $outputBuffer = & $this->_output;
        }

        // convenience variables
        $fdInput   = $this->_pipes[self::FD_INPUT];
        $fdOutput  = $this->_pipes[self::FD_OUTPUT];
        $fdError   = $this->_pipes[self::FD_ERROR];
        $fdStatus  = $this->_pipes[self::FD_STATUS];
        $fdCommand = $this->_pipes[self::FD_COMMAND];
        $fdMessage = $this->_pipes[self::FD_MESSAGE];

        // Ignore "Broken pipe" notice from fwrite() below, as gpg could close
        // the command stream before we finished writing (e.g. in bad passphrase case).
        set_error_handler(function ($errno, $errstr, $errfile, $errline) {
            return str_contains($errfile, 'Engine.php') && str_contains($errstr, 'errno=32');
        }, E_NOTICE);

        // select loop delay in milliseconds
        $delay         = 0;
        $inputPosition = 0;
        $eolLength     = strlen(PHP_EOL);

        while (true) {
            $inputStreams     = [];
            $outputStreams    = [];
            $exceptionStreams = [];

            // set up input streams
            if (is_resource($this->_input) && !$inputComplete) {
                if (feof($this->_input)) {
                    $inputComplete = true;
                } else {
                    $inputStreams[] = $this->_input;
                }
            }

            // close GPG input pipe if there is no more data
            if ($inputBuffer == '' && $inputComplete) {
                $this->_debug('=> closing GPG input pipe');
                $this->_closePipe(self::FD_INPUT);
            }

            if (is_resource($this->_message) && !$messageComplete) {
                if (feof($this->_message)) {
                    $messageComplete = true;
                } else {
                    $inputStreams[] = $this->_message;
                }
            }

            // close GPG message pipe if there is no more data
            if ($messageBuffer == '' && $messageComplete) {
                $this->_debug('=> closing GPG message pipe');
                $this->_closePipe(self::FD_MESSAGE);
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

            if ($this->_commandBuffer != '' && is_resource($fdCommand)) {
                $outputStreams[] = $fdCommand;
            }

            if ($messageBuffer != '' && is_resource($fdMessage)) {
                $outputStreams[] = $fdMessage;
            }

            if ($inputBuffer != '' && is_resource($fdInput)) {
                $outputStreams[] = $fdInput;
            }

            // no streams left to read or write, we're all done
            if (count($inputStreams) === 0 && count($outputStreams) === 0) {
                break;
            }

            $this->_debug('selecting streams');

            $ready = stream_select($inputStreams, $outputStreams, $exceptionStreams, null);

            $this->_debug('=> got ' . $ready);

            if ($ready === false) {
                throw new Exceptions\Exception(
                    'Error selecting stream for communication with GPG '
                    . 'subprocess. Please file a bug report at: ' . GPG::BUG_URI
                );
            }

            if ($ready === 0) {
                throw new Exceptions\Exception(
                    'stream_select() returned 0. This can not happen! Please '
                    . 'file a bug report at: ' . GPG::BUG_URI
                );
            }

            // write input (to GPG)
            if (in_array($fdInput, $outputStreams, true)) {
                $this->_debug('GPG is ready for input');

                $chunk  = substr($inputBuffer, $inputPosition, self::CHUNK_SIZE);
                $length = strlen($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes to GPG input');

                $length = fwrite($fdInput, $chunk, $length);
                if ($length === 0 || $length === false) {
                    // If we wrote 0 bytes it was either EAGAIN or EPIPE. Since
                    // the pipe was seleted for writing, we assume it was EPIPE.
                    // There's no way to get the actual error code in PHP. See
                    // PHP Bug #39598. https://bugs.php.net/bug.php?id=39598
                    $this->_debug('=> broken pipe on GPG input');
                    $this->_debug('=> closing pipe GPG input');
                    $this->_closePipe(self::FD_INPUT);
                } else {
                    $this->_debug('=> wrote ' . $length . ' bytes');
                    // Move the position pointer, don't modify $inputBuffer (#21081)
                    if (is_string($this->_input)) {
                        $inputPosition += $length;
                    } else {
                        $inputPosition = 0;
                        $inputBuffer   = substr($inputBuffer, $length);
                    }
                }
            }

            // read input (from PHP stream)
            // If the buffer is too big wait until it's smaller, we don't want
            // to use too much memory
            if (in_array($this->_input, $inputStreams, true) && strlen($inputBuffer) < self::CHUNK_SIZE) {
                $this->_debug('input stream is ready for reading');
                $this->_debug(
                    '=> about to read ' . self::CHUNK_SIZE
                    . ' bytes from input stream'
                );

                $chunk        = fread($this->_input, self::CHUNK_SIZE);
                $length       = strlen($chunk);
                $inputBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');
            }

            // write message (to GPG)
            if (in_array($fdMessage, $outputStreams, true)) {
                $this->_debug('GPG is ready for message data');

                $chunk  = substr($messageBuffer, 0, self::CHUNK_SIZE);
                $length = strlen($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes to GPG message');

                $length = fwrite($fdMessage, $chunk, $length);

                if ($length === 0 || $length === false) {
                    // If we wrote 0 bytes it was either EAGAIN or EPIPE. Since
                    // the pipe was seleted for writing, we assume it was EPIPE.
                    // There's no way to get the actual error code in PHP. See
                    // PHP Bug #39598. https://bugs.php.net/bug.php?id=39598
                    $this->_debug('=> broken pipe on GPG message');
                    $this->_debug('=> closing pipe GPG message');
                    $this->_closePipe(self::FD_MESSAGE);
                } else {
                    $this->_debug('=> wrote ' . $length . ' bytes');
                    $messageBuffer = substr($messageBuffer, $length);
                }
            }

            // read message (from PHP stream)
            if (in_array($this->_message, $inputStreams, true)) {
                $this->_debug('message stream is ready for reading');
                $this->_debug(
                    '=> about to read ' . self::CHUNK_SIZE
                    . ' bytes from message stream'
                );

                $chunk          = fread($this->_message, self::CHUNK_SIZE);
                $length         = strlen($chunk);
                $messageBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');
            }

            // read output (from GPG)
            if (in_array($fdOutput, $inputStreams, true)) {
                $this->_debug('GPG output stream ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE . ' bytes from GPG output');

                $chunk         = fread($fdOutput, self::CHUNK_SIZE);
                $length        = strlen($chunk);
                $outputBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');
            }

            // write output (to PHP stream)
            if (in_array($this->_output, $outputStreams, true)) {
                $this->_debug('output stream is ready for data');

                $chunk  = substr($outputBuffer, 0, self::CHUNK_SIZE);
                $length = strlen($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes to output stream');

                $length = fwrite($this->_output, $chunk, $length);

                if ($length === 0 || $length === false) {
                    // If we wrote 0 bytes it was either EAGAIN or EPIPE. Since
                    // the pipe was seleted for writing, we assume it was EPIPE.
                    // There's no way to get the actual error code in PHP. See
                    // PHP Bug #39598. https://bugs.php.net/bug.php?id=39598
                    $this->_debug('=> broken pipe on output stream');
                    $this->_debug('=> closing pipe output stream');
                    $this->_closePipe(self::FD_OUTPUT);
                } else {
                    $this->_debug('=> wrote ' . $length . ' bytes');
                    $outputBuffer = substr($outputBuffer, $length);
                }
            }

            // read error (from GPG)
            if (in_array($fdError, $inputStreams, true)) {
                $this->_debug('GPG error stream ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE . ' bytes from GPG error');

                $chunk        = fread($fdError, self::CHUNK_SIZE);
                $length       = strlen($chunk);
                $errorBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');

                // pass lines to error handlers
                while (($pos = strpos($errorBuffer, PHP_EOL)) !== false) {
                    $line = substr($errorBuffer, 0, $pos);
                    foreach ($this->_errorHandlers as $handler) {
                        array_unshift($handler['args'], $line);
                        call_user_func_array($handler['callback'], $handler['args']);
                        array_shift($handler['args']);
                    }

                    $errorBuffer = substr($errorBuffer, $pos + $eolLength);
                }
            }

            // read status (from GPG)
            if (in_array($fdStatus, $inputStreams, true)) {
                $this->_debug('GPG status stream ready for reading');
                $this->_debug('=> about to read ' . self::CHUNK_SIZE . ' bytes from GPG status');

                $chunk         = fread($fdStatus, self::CHUNK_SIZE);
                $length        = strlen($chunk);
                $statusBuffer .= $chunk;

                $this->_debug('=> read ' . $length . ' bytes');

                // pass lines to status handlers
                while (($pos = strpos($statusBuffer, PHP_EOL)) !== false) {
                    $line = substr($statusBuffer, 0, $pos);
                    // only pass lines beginning with magic prefix
                    if (str_starts_with($line, '[GNUPG:] ')) {
                        $line = substr($line, 9);
                        foreach ($this->_statusHandlers as $handler) {
                            array_unshift($handler['args'], $line);
                            call_user_func_array(
                                $handler['callback'],
                                $handler['args']
                            );

                            array_shift($handler['args']);
                        }
                    }

                    $statusBuffer = substr($statusBuffer, $pos + $eolLength);
                }
            }

            // write command (to GPG)
            if (in_array($fdCommand, $outputStreams, true)) {
                $this->_debug('GPG is ready for command data');

                // send commands
                $chunk  = substr($this->_commandBuffer, 0, self::CHUNK_SIZE);
                $length = strlen($chunk);

                $this->_debug('=> about to write ' . $length . ' bytes to GPG command');

                $length = fwrite($fdCommand, $chunk, $length);

                if ($length === 0 || $length === false) {
                    // If we wrote 0 bytes it was either EAGAIN or EPIPE. Since
                    // the pipe was seleted for writing, we assume it was EPIPE.
                    // There's no way to get the actual error code in PHP. See
                    // PHP Bug #39598. https://bugs.php.net/bug.php?id=39598
                    $this->_debug('=> broken pipe on GPG command');
                    $this->_debug('=> closing pipe GPG command');
                    $this->_closePipe(self::FD_COMMAND);
                } else {
                    $this->_debug('=> wrote ' . $length);
                    $this->_commandBuffer = substr($this->_commandBuffer, $length);
                }
            }

            if (count($outputStreams) === 0 || count($inputStreams) === 0) {
                // we have an I/O imbalance, increase the select loop delay
                // to smooth things out
                $delay += 10;
            } else {
                // things are running smoothly, decrease the delay
                $delay -= 8;
                $delay = max(0, $delay);
            }

            if ($delay > 0) {
                usleep($delay);
            }

        } // end loop while streams are open

        restore_error_handler();

        $this->_debug('END PROCESSING');
    }

    /**
     * Opens an internal GPG subprocess for the current operation
     *
     * Opens a GPG subprocess, then connects the subprocess to some pipes. Sets
     * the private class property {@link Crypt\GPG\Engine::$_process} to
     * the new subprocess.
     *
     * @throws Exceptions\OpenSubprocessException if the subprocess could not be opened.
     *
     * @see self::setOperation()
     * @see self::_closeSubprocess()
     * @see self::$_process
     */
    private function _openSubprocess(): void
    {
        $version = $this->getVersion();

        // log versions, but not when looking for the version number
        if ($version !== '1.0.0') {
            $this->_debug('USING GPG ' . $version . ' with PHP ' . PHP_VERSION);
        }

        // Get environment variables. Exclude non-scalar values to prevent from a warning in proc_open().
        // Possibly related to https://bugs.php.net/bug.php?id=75712, which was fixed in PHP 8.2.17.
        $env = array_filter($_ENV, 'is_scalar');

        // Newer versions of GnuPG return localized results. Crypt_GPG only
        // works with English, so set the locale to 'C' for the subprocess.
        $env['LC_ALL'] = 'C';

        $commandLine = $this->_binary;

        $defaultArguments = [
            '--status-fd ' . escapeshellarg((string) self::FD_STATUS),
            '--command-fd ' . escapeshellarg((string) self::FD_COMMAND),
            '--no-secmem-warning',
            '--no-tty',
            '--no-default-keyring', // ignored if keying files are not specified
            '--no-options',          // prevent creation of ~/.gnupg directory
            '--no-permission-warning',
            '--exit-on-status-write-error',
            '--trust-model always',
            '--pinentry-mode loopback',
        ];

        if (!$this->_strict) {
            $defaultArguments[] = '--ignore-time-conflict';
            $defaultArguments[] = '--ignore-valid-from';
        }

        if (!empty($this->_digest_algo)) {
            $defaultArguments[] = '--digest-algo ' . escapeshellarg($this->_digest_algo);
            $defaultArguments[] = '--s2k-digest-algo ' . escapeshellarg($this->_digest_algo);
        }

        if (!empty($this->_cipher_algo)) {
            $defaultArguments[] = '--cipher-algo ' . escapeshellarg($this->_cipher_algo);
            $defaultArguments[] = '--s2k-cipher-algo ' . escapeshellarg($this->_cipher_algo);
        }

        if (!empty($this->_compress_algo)) {
            $defaultArguments[] = '--compress-algo ' . escapeshellarg($this->_compress_algo);
        }

        $arguments = array_merge($defaultArguments, $this->_arguments);

        if ($this->_homedir) {
            $arguments[] = '--homedir ' . escapeshellarg($this->_homedir);

            // the random seed file makes subsequent actions faster so only
            // disable it if we have to.
            if (!is_writeable($this->_homedir)) {
                $arguments[] = '--no-random-seed-file';
            }
        }

        if ($this->_publicKeyring) {
            $arguments[] = '--keyring ' . escapeshellarg($this->_publicKeyring);
        }

        if ($this->_privateKeyring) {
            $arguments[] = '--secret-keyring ' . escapeshellarg($this->_privateKeyring);
        }

        if ($this->_trustDb) {
            $arguments[] = '--trustdb-name ' . escapeshellarg($this->_trustDb);
        }

        $commandLine .= ' ' . implode(' ', $arguments) . ' ' . $this->_operation;

        $descriptorSpec = [
            self::FD_INPUT   => ['pipe', 'rb'], // stdin
            self::FD_OUTPUT  => ['pipe', 'wb'], // stdout
            self::FD_ERROR   => ['pipe', 'wb'], // stderr
            self::FD_STATUS  => ['pipe', 'wb'], // status
            self::FD_COMMAND => ['pipe', 'rb'], // command
            self::FD_MESSAGE => ['pipe', 'rb'],  // message
        ];

        $this->_debug('OPENING GPG SUBPROCESS WITH THE FOLLOWING COMMAND:');
        $this->_debug($commandLine);

        $this->_process = proc_open(
            $commandLine,
            $descriptorSpec,
            $this->_pipes,
            null,
            $env,
            ['binary_pipes' => true]
        );

        if (!is_resource($this->_process)) {
            throw new Exceptions\OpenSubprocessException(
                'Unable to open GPG subprocess.',
                0,
                $commandLine
            );
        }

        // Set streams as non-blocking. See Bug #18618.
        foreach ($this->_pipes as $pipe) {
            stream_set_blocking($pipe, false);
            stream_set_write_buffer($pipe, self::CHUNK_SIZE);
            stream_set_chunk_size($pipe, self::CHUNK_SIZE);
            stream_set_read_buffer($pipe, self::CHUNK_SIZE);
        }

        $this->_openPipes = $this->_pipes;
    }

    /**
     * Closes the internal GPG subprocess
     *
     * Closes the internal GPG subprocess. Sets the private class property
     * {@link self::$_process} to null.
     *
     * @see self::_openSubprocess()
     * @see self::$_process
     */
    private function _closeSubprocess(): void
    {
        // clear PINs from environment if they were set
        $_ENV['PINENTRY_USER_DATA'] = null;

        if (is_resource($this->_process)) {
            $this->_debug('CLOSING GPG SUBPROCESS');

            // close remaining open pipes
            foreach (array_keys($this->_openPipes) as $pipeNumber) {
                $this->_closePipe($pipeNumber);
            }

            $status   = proc_get_status($this->_process);
            $exitCode = proc_close($this->_process);

            // proc_close() can return -1 in some cases,
            // get the real exit code from the process status
            if ($exitCode < 0 && !$status['running']) {
                $exitCode = $status['exitcode'];
            }

            if ($exitCode > 0) {
                $this->_debug('=> subprocess returned an unexpected exit code: ' . $exitCode);
            }

            $this->_process = null;
            $this->_pipes   = [];

            // close file handles before throwing an exception
            if (is_resource($this->_input)) {
                fclose($this->_input);
            }

            if (is_resource($this->_output)) {
                fclose($this->_output);
            }

            $this->_processHandler->throwException($exitCode);
        }
    }

    /**
     * Closes an opened pipe used to communicate with the GPG subprocess
     *
     * If the pipe is already closed, it is ignored. If the pipe is open, it
     * is flushed and then closed.
     *
     * @param int $pipeNumber The file descriptor number of the pipe to close
     */
    private function _closePipe($pipeNumber): void
    {
        $pipeNumber = intval($pipeNumber);
        if (array_key_exists($pipeNumber, $this->_openPipes)) {
            fflush($this->_openPipes[$pipeNumber]);
            fclose($this->_openPipes[$pipeNumber]);
            unset($this->_openPipes[$pipeNumber]);
        }
    }

    /**
     * Gets the name of the GPG binary for the current operating system
     *
     * This method is called if the '<kbd>binary</kbd>' option is <i>not</i>
     * specified when creating this driver.
     *
     * @return string the name of the GPG binary for the current operating
     *                system. If no suitable binary could be found, an empty
     *                string is returned.
     */
    private function _getBinary(): string
    {
        if ($binary = $this->_findBinary('gpg')) {
            return $binary;
        }

        return $this->_findBinary('gpg2');
    }

    /**
     * Gets the location of a binary for the current operating system
     *
     * @param string $name Name of a binary program
     *
     * @return string The location of the binary for the current operating
     *                system. If no suitable binary could be found, an empty
     *                string is returned.
     */
    private function _findBinary($name): string
    {
        if ($this->_isDarwin) {
            $locations = [
                '/opt/local/bin/', // MacPorts
                '/usr/local/bin/', // Mac GPG
                '/sw/bin/',        // Fink
                '/usr/bin/',
            ];
        } else {
            $locations = [
                '/usr/bin/',
                '/usr/local/bin/',
                '/run/current-system/sw/bin/', // NixOS
            ];
        }

        foreach ($locations as $location) {
            if (is_executable($location . $name)) {
                return $location . $name;
            }
        }

        return '';
    }

    /**
     * Displays debug text if debugging is turned on
     *
     * Debugging text is prepended with a debug identifier and echoed to stdout.
     *
     * @param string $text the debugging text to display.
     */
    private function _debug($text): void
    {
        if ($this->_debug) {
            if (is_callable($this->_debug)) {
                call_user_func($this->_debug, $text);
            } elseif (php_sapi_name() === 'cli') {
                foreach (explode(PHP_EOL, $text) as $line) {
                    echo "Crypt_GPG DEBUG: ", $line, PHP_EOL;
                }
            } else {
                // running on a web server, format debug output nicely
                foreach (explode(PHP_EOL, $text) as $line) {
                    echo "Crypt_GPG DEBUG: <strong>", htmlspecialchars($line), '</strong><br />', PHP_EOL;
                }
            }
        }
    }
}
