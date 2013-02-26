<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

require_once 'Console/CommandLine.php';

class Crypt_GPG_PinEntry
{
    const VERBOSITY_NONE = 0;
    const VERBOSITY_ERRORS = 1;
    const VERBOSITY_ALL = 2;

    const READ_BUFFER_LENGTH = 8192;

    /** 
     * @var resource
     */
    protected $stdin = null;

    /** 
     * @var resource
     */
    protected $stdout = null;

    /** 
     * @var resource
     */
    protected $logFile = null;

    /**
     * @var string
     */
    protected $logFilename = '';

    /**
     * Whether or not this pinentry is finished and is exiting
     *
     * @var boolean
     */
    protected $moribund = false;

    /**
     * @var integer
     */
    protected $verbosity = self::VERBOSITY_NONE;

    /**
     * @var Console_CommandLine
     */
    protected $parser = null;

    /**
     * @var array
     */
    protected $pins = array();

    /**
     * @var array
     */
    protected $triedPins = array();

    /**
     * @var array|null
     */
    protected $currentPin = null;

    public function __invoke()
    {
        $this->parser = $this->getParser();

        try {
            $result = $this->parser->parse();

            $this->setVerbosity($result->options['verbose']);
            $this->logFilename = $result->options['log'];

            $this->connect();
            $this->initPinsFromEnv();

            $this->send($this->ok('Crypt_GPG pinentry ready and waiting'));
            while (($line = fgets($this->stdin, self::READ_BUFFER_LENGTH)) !== false) {
                $this->parseCommand(mb_substr($line, 0, -1, '8bit'));
                if ($this->moribund) {
                    break;
                }
            }

            $this->disconnect();

        } catch (Console_CommandLineException $e) {
            $this->log($e->getMessage() . PHP_EOL, slf::VERBOSITY_ERRORS);
            exit(1);
        } catch (Exception $e) {
            $this->log($e->getMessage() . PHP_EOL, self::VERBOSITY_ERRORS);
            $this->log($e->getTraceAsString() . PHP_EOL, self::VERBOSITY_ERRORS);
            exit(1);
        }
    }

    public function setVerbosity($verbosity)
    {
        $this->verbosity = (integer)$verbosity;
    }

    protected function getUIXML()
    {
        $dir = '@data-dir@' . DIRECTORY_SEPARATOR
            . '@package-name@' . DIRECTORY_SEPARATOR . 'data';

        // Check if we're running directly from a git checkout or if we're
        // running from a PEAR-packaged version.
        if ($dir[0] == '@') {
            $dir = dirname(__FILE__) . DIRECTORY_SEPARATOR . '..'
                . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'data';
        }

        return $dir . DIRECTORY_SEPARATOR . 'pinentry-cli.xml';
    }

    protected function getParser()
    {
        return Console_CommandLine::fromXmlFile($this->getUIXML());
    }

    protected function log($data, $level)
    {
        if ($this->verbosity >= $level) {
            if (is_resource($this->logFile)) {
                fwrite($this->logFile, $data);
                fflush($this->logFile);
            } else {
                $this->parser->outputter->output($data);
            }
        }
    }

    protected function parseCommand($line)
    {
        $this->log('<- ' . $line . PHP_EOL, self::VERBOSITY_ALL);

        $parts = explode(' ', $line, 2);

        $command = $parts[0];

        if (count($parts) === 2) {
            $data = $parts[1];
        } else {
            $data = null;
        }

        switch ($command) {
        case 'SETDESC':
            return $this->setDescription($data);

        case 'SETPROMPT':
        case 'SETERROR':
        case 'SETOK':
        case 'SETNOTOK':
        case 'SETCANCEL':
        case 'SETQUALITYBAR':
        case 'SETQUALITYBAR_TT':
        case 'OPTION':
            return $this->notImplementedOk();

        case 'MESSAGE':
            return $this->message();

        case 'CONFIRM':
            return $this->confirm();

        case 'GETINFO':
            return $this->getInfo($data);

        case 'GETPIN':
            return $this->getPin($data);

        case 'RESET':
            return $this->reset();

        case 'BYE':
            return $this->bye();
        }
    }

    protected function connect()
    {
        $this->stdin  = fopen('php://stdin', 'rb');
        $this->stdout = fopen('php://stdout', 'wb');

        if (function_exists('stream_set_read_buffer')) {
            stream_set_read_buffer($this->stdin, 0);
        }
        stream_set_write_buffer($this->stdout, 0);

        if ($this->logFilename != '') {
            if (($this->logFile = fopen($this->logFilename, 'wb')) === false) {
                $this->log(
                    'Unable to open log file "' . $this->logFilename . '" '
                    . 'for writing.' . PHP_EOL,
                    self::VERBOSITY_ERRORS
                );
                exit(1);
            } else {
                stream_set_write_buffer($this->logFile, 0);
            }
        }
    }

    protected function initPinsFromEnv()
    {
        if (($userData = getenv('PINENTRY_USER_DATA')) !== false) {
            $pins = json_decode($userData, true);
            if ($pins !== null) {
                $this->pins = $pins;
            }
            $this->log(
                '-- got user data ' . $userData . PHP_EOL,
                self::VERBOSITY_ALL
            );
        }
    }

    protected function disconnect()
    {
        fflush($this->stdout);
        fclose($this->stdout);
        fclose($this->stdin);

        $this->stdin  = null;
        $this->stdout = null;

        if (is_resource($this->logFile)) {
            fflush($this->logFile);
            fclose($this->logFile);
            $this->logFile = null;
        }
    }

    /**
     * Sends an OK response for a not implemented feature
     *
     * @return void
     */
    protected function notImplementedOk()
    {
        $this->send($this->ok());
    }

    /**
     * Parses the currently requested key identifier and user identifier from
     * the description passed to this pinentry
     *
     * @param string $text the raw description sent from gpg-agent.
     *
     * @return void
     */
    protected function setDescription($text)
    {
        $text = rawurldecode($text);
        $matches = array();
        // TODO: handle user id with quotation marks
        $exp = '/\n"(.+)"\n.*\sID ([A-Z0-9]+),\n/mu';
        if (preg_match($exp, $text, $matches) === 1) {
            $userId = $matches[1];
            $keyId  = $matches[2];

            // only reset tried pins for new requested pin
            if (   $this->currentPin === null
                || $this->currentPin['keyId'] !== $keyId
            ) {
                $this->currentPin = array(
                    'userId' => $userId,
                    'keyId'  => $keyId
                );
                $this->triedPins = array();
                $this->log(
                    '-- looking for PIN for ' . $keyId . PHP_EOL,
                    self::VERBOSITY_ALL
                );
            }
        }

        $this->send($this->ok());
    }

    protected function confirm($text)
    {
        $this->send($this->buttonInfo('close'));
    }

    protected function message($text)
    {
        $this->send($this->buttonInfo('close'));
    }

    protected function buttonInfo($text)
    {
        $this->send('BUTTON_INFO ' . $text . "\n");
    }

    protected function getPin()
    {
        $foundPin = '';

        if (is_array($this->currentPin)) {
            $keyIdLength = mb_strlen($this->currentPin['keyId'], '8bit');

            // search for the pin
            foreach ($this->pins as $pin) {
                // only check pins we haven't tried
                if (!isset($this->triedPins[$pin['keyId']])) {

                    // get last X characters of key identifier to compare
                    $keyId = mb_substr(
                        $pin['keyId'],
                        -$keyIdLength,
                        mb_strlen($pin['keyId'], '8bit'),
                        '8bit'
                    );

                    if ($keyId === $this->currentPin['keyId']) {
                        $foundPin = $pin['passphrase'];
                        $this->triedPins[$pin['keyId']] = $pin;
                        break;
                    }
                }
            }
        }

        $this->send($this->data($foundPin));
        $this->send($this->ok());
    }

    protected function getInfo($data)
    {
        $parts = explode(' ', $data, 2);
        $command = reset($parts);

        switch ($command) {
        case 'pid':
            $this->getInfoPID();
            $this->send($this->ok());
            return;
        default:
            $this->send($this->ok());
            return;
        }
    }

    protected function getInfoPID()
    {
        return $this->send($this->data(getmypid()));
    }

    protected function bye()
    {
        $this->send($this->ok('closing connection'));
        $this->moribund = true;
    }

    protected function reset()
    {
        $this->send($this->ok());
    }

    protected function ok($data = null)
    {
        $return = 'OK';

        if ($data) {
            $return .= ' ' . $data;
        }

        return $return . "\n";
    }

    protected function data($data)
    {
        // Escape data. Only %, \n and \r need to be escaped but other
        // values are allowed to be escaped. See 
        // http://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
        $data = rawurlencode($data);
        $data = $this->wordWrap($data, 'D');
        return $data;
    }

    protected function comment($data)
    {
        return $this->wordWrap($data, '#');
    }

    protected function send($data)
    {
        $this->log('-> ' . $data, self::VERBOSITY_ALL);
        fwrite($this->stdout, $data);
        fflush($this->stdout);
    }

    /**
     * @param string $data   
     * @param string $prefix 
     *
     * Protocol strings are UTF-8 but maximum line length is 1,000 bytes.
     * <kbd>mb_strcut()</kbd> is used so we can limit line length by bytes
     * and not split characters across multiple lines.
     *
     * @see http://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
     */
    protected function wordWrap($data, $prefix)
    {
        $lines = array();

        do {
            if (mb_strlen($data, '8bit') > 997) {
                $line = $prefix . ' ' . mb_strcut($data, 0, 996, 'utf-8') . "\\\n";
                $lines[] = $line;
                $lineLength = mb_strlen($line, '8bit') - 1;
                $dataLength = mb_substr($data, '8bit');
                $data = mb_substr(
                    $data,
                    $lineLength,
                    $dataLength - $lineLength,
                    '8bit'
                );
            } else {
                $lines[] = $prefix . ' ' . $data . "\n";
                $data = '';
            }
        } while ($data != '');

        return implode('', $lines);
    }
}

?>
