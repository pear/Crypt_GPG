<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

require_once 'Console/CommandLine.php';
require_once 'Crypt/GPG/ByteUtils.php';

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

    public function __invoke()
    {
        $this->parser = $this->getParser();

        try {
            $result = $this->parser->parse();

            $this->setVerbosity($result->options['verbose']);
            $this->logFilename = $result->options['log'];

            $this->connect();

            $this->send($this->ok('Crypt_GPG pinentry ready and waiting'));
            while (($line = fgets($this->stdin, self::READ_BUFFER_LENGTH)) !== false) {
                $this->parseCommand(Crypt_GPG_ByteUtils::substr($line, 0, -1));
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
            if (is_resource($this->log)) {
                fwrite($this->log, $data);
                fflush($this->log);
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

    protected function notImplementedOk()
    {
        // not implemented
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
        // TODO: grab from pipe
        $this->send($this->data('test'));
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

        if (Crypt_GPG_ByteUtils::strlen($data) > 1000) {
            // TODO: break on multiple lines
        }

        return 'D ' . $data . "\n";
    }

    protected function comment($data)
    {
        if (Crypt_GPG_ByteUtils::strlen($data) > 1000) {
            // TODO: break on multiple lines
        }

        return '# ' . $data . "\n";
    }

    protected function send($data)
    {
        $this->log('-> ' . $data, self::VERBOSITY_ALL);
        fwrite($this->stdout, $data);
        fflush($this->stdout);
    }
}

?>
