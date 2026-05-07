<?php

namespace Crypt\Console;

require_once __DIR__ . '/PinCliParameters.php';

class SimpleCliWrapper
{
    const DEFAULT_VERBOSITY = 0;
    const INVALID_INPUT = -1;
    const VERBOSE_LONG = 'verbose';
    const VERBOSE_SHORT = 'v';
    const HELP_SHORT = 'h';
    const HELP_LONG = 'help';
    const LOG_SHORT = 'l';
    const LOG_LONG = 'log';
    const OPTIONAL_INDICATOR = '::';

    /**
     * The old definition for the CLI options was:
     * ```xml
     *  <description>Utility that emulates GnuPG 1.x passphrase handling over pipe-based IPC for GnuPG 2.x.</description>
     *      <version>@package-version@</version>
     *      <option name="log">
     *          <short_name>-l</short_name>
     *          <long_name>--log</long_name>
     *          <description>Optional location to log pinentry activity.</description>
     *          <action>StoreString</action>
     *      </option>
     *          <option name="verbose">
     *          <short_name>-v</short_name>
     *          <long_name>--verbose</long_name>
     *          <description>Sets verbosity level. Use multiples for more detail (e.g. "-vv").</description>
     *          <action>Counter</action>
     *          <default>0</default>
     *      </option>
     *  </description>
     * ```
     *
     * @return PinCliParameters
     */
    public function parseCli()
    {
        $shortOpts = implode('', [
            self::VERBOSE_SHORT . self::OPTIONAL_INDICATOR,
            self::LOG_SHORT . self::OPTIONAL_INDICATOR,
            self::HELP_SHORT . self::OPTIONAL_INDICATOR
        ]);

        $longOpts = [
            self::VERBOSE_LONG . self::OPTIONAL_INDICATOR,
            self::LOG_LONG . self::OPTIONAL_INDICATOR,
            self::HELP_LONG . self::OPTIONAL_INDICATOR
        ];

        $opts = getopt($shortOpts, $longOpts);
        if (isset($opts[self::HELP_SHORT]) || isset($opts[self::HELP_LONG])) {
            $this->printHelp();
            exit(1);
        }

        $verbosityLevel = self::getVerbosityLevel($opts);
        if ($verbosityLevel === self::INVALID_INPUT) {
            $this->writeToErrOrEcho("Invalid verbosity level. Please use -h or --help.\n");
            exit(1);
        }

        $logLocation = self::getLogLocation($opts);
        if ($logLocation === self::INVALID_INPUT) {
            $this->writeToErrOrEcho("Invalid log location. Please use -h or --help.\n");
            exit(1);
        }

        return new PinCliParameters(
            $verbosityLevel,
            $logLocation
        );
    }

    /**
     * replication of previous behavior from PEAR Console_CommandLine
     * which is abandoned now.
     *
     * ```
     * public function stderr($msg)
     * {
     *      if (defined('STDERR')) {
     *          fwrite(STDERR, $msg);
     *      } else {
     *          echo $msg;
     *      }
     * }
     * ```
     *
     * @return void
     */
    public function writeToErrOrEcho($msg)
    {
        if (defined('STDERR')) {
            fwrite(STDERR, $msg);
        } else {
            echo $msg;
        }
    }

    private function printHelp()
    {
        echo "
Utility that emulates GnuPG 1.x passphrase handling over pipe-based IPC for GnuPG 2.x.

Options:
    -h, --help: Display this help message.
    -l, --log: Optional location to log pinentry activity.
    -v, --verbose: Verbosity level for logging.
    
    The default verbosity level is 0.
    Increase verbosity levels for more detail:
        Short Syntax: -vvv
        Long Syntax: --verbose 3
    
    Set the Log Location:
        Short Syntax: -l/path/to/log/file
        Long Syntax: --log /path/to/log/file
    
    the short syntax will be taken before the long syntax.
";
    }

    /**
     * @return int
     */
    public static function getVerbosityLevel(array $opts)
    {
        if (!isset($opts[self::VERBOSE_SHORT]) && !isset($opts[self::VERBOSE_LONG])) {
            return self::DEFAULT_VERBOSITY;
        }

        // the default options with just a -v is false, but based
        // on the old system, it would be level 0
        if (isset($opts[self::VERBOSE_SHORT])) {
            if ($opts[self::VERBOSE_SHORT] === false) {
                return self::DEFAULT_VERBOSITY;
            }

            // the first v will be stripped -v so we count the amounts of v's after that
            return (int)mb_strlen($opts[self::VERBOSE_SHORT]);
        }

        if (isset($opts[self::VERBOSE_LONG]) && !is_numeric($opts[self::VERBOSE_LONG])) {
            return self::INVALID_INPUT;
        }

        if (isset($opts[self::VERBOSE_LONG])) {
            return (int)$opts[self::VERBOSE_LONG];
        }

        return self::INVALID_INPUT;

    }

    public static function getLogLocation(array $opts)
    {
        if (!isset($opts[self::LOG_SHORT]) && !isset($opts[self::LOG_LONG])) {
            return '';
        }

        if (isset($opts[self::LOG_SHORT]) && is_string($opts[self::LOG_SHORT])) {
            return $opts[self::LOG_SHORT];
        }

        if (isset($opts[self::LOG_LONG]) && is_string($opts[self::LOG_LONG])) {
            return $opts[self::LOG_LONG];
        }

        return self::INVALID_INPUT;
    }
}
