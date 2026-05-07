<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

require_once 'Crypt/GPG/Engine.php';

/**
 * A class for editing keys (using GnuPG interactive --key-edit shell)
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
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/>
 *
 * @category  Encryption
 * @package   Crypt_GPG
 * @author    Aleksander Machniak <machniak@apheleia-it.ch>
 * @copyright Apheleia IT AG <contact@apheleia-it.ch>
 * @license   http://www.gnu.org/copyleft/lesser.html LGPL License 2.1
 * @link      http://pear.php.net/package/Crypt_GPG
 */
class Crypt_GPG_KeyEditor
{
    /** @var array The GnuPG engine/key editor options */
    protected $options;

    /** @var Crypt_GPG_Engine The GnuPG engine */
    protected $engine;

    protected $key;
    protected $passphrase = '';
    protected $process;
    protected $pipes = [];

    /**
     * Creates a new key editor
     *
     * @param Crypt_GPG_Engine $engine  GnuPG engine
     * @param array            $options GnuPG engine options
     */
    public function __construct($engine, array $options)
    {
        $this->engine = $engine;
        $this->options = $options;
    }

    /**
     * Closes open GPG subprocesses when this object is destroyed.
     *
     * Subprocesses should never be left open by this class unless there is
     * an unknown error and an unexpected script termination occured.
     */
    public function __destruct()
    {
        $this->_close();
    }

    /**
     * Starts key editing session
     *
     * @param mixed  $key        The key to use. This may be a key identifier, user id, fingerprint,
     *                           {@link Crypt_GPG_Key} or {@link Crypt_GPG_SubKey}.
     * @param string $passphrase The passphrase of the key required for signing (optional).
     *
     * @return Crypt_GPG_KeyEditor The current object, for fluent interface.
     *
     * @sensitive $passphrase
     */
    public function edit($key, $passphrase = null)
    {
        if ($this->key && $this->process) {
            $this->save();
            $this->_close();
        }

        $this->key = (string) $key;
        $this->passphrase = (string) $passphrase;

        $version = $this->engine->getVersion();

        // Since 2.1.13 we can use "loopback mode" instead of gpg-agent
        // We do not support older versions here
        if (!version_compare($version, '2.1.13', 'ge')) {
            throw new PEAR_Exception("Key editor requires GnuPG >= 2.1.13");
        }

        $arguments = [
            '--no-default-keyring', // ignored if keyring files are not specified
            '--no-options',         // prevent creation of ~/.gnupg directory
            '--no-permission-warning',
            '--trust-model always',
            '--homedir ' . escapeshellarg($this->options['homedir']),
            '--pinentry-mode loopback', // passphrase input in stdin
            '--command-fd ' . escapeshellarg(Crypt_GPG_Engine::FD_INPUT),
            '--status-fd ' . escapeshellarg(Crypt_GPG_Engine::FD_ERROR),
            '--batch',
            '--yes',
        ];

        // the random seed file makes subsequent actions faster so only
        // disable it if we have to.
        if (!is_writeable($this->options['homedir'])) {
            $arguments[] = '--no-random-seed-file';
        }

        if (!empty($this->options['publicKeyring'])) {
            $arguments[] = '--keyring ' . escapeshellarg($this->options['publicKeyring']);
        }

        if (!empty($this->options['privateKeyring'])) {
            $arguments[] = '--secret-keyring ' . escapeshellarg($this->options['privateKeyring']);
        }

        if (!empty($this->options['trustDb'])) {
            $arguments[] = '--trustdb-name ' . escapeshellarg($this->options['trustDb']);
        }

        $command = $this->options['binary'] . ' ' . implode(' ', $arguments) . ' --edit-key ' . escapeshellarg($this->key);

        $this->_debug("OPENING GPG SUBPROCESS WITH THE FOLLOWING COMMAND:");
        $this->_debug($command);

        // Get environment variables. Exclude non-scalar values to prevent from a warning in proc_open().
        // Possibly related to https://bugs.php.net/bug.php?id=75712, which was fixed in PHP 8.2.17.
        $env = array_filter($_ENV, 'is_scalar');

        // Newer versions of GnuPG return localized results. Crypt_GPG only
        // works with English, so set the locale to 'C' for the subprocess.
        $env['LC_ALL'] = 'C';

        $specs = [
            Crypt_GPG_Engine::FD_INPUT => ['pipe', 'r'],
            // Crypt_GPG_Engine::FD_OUTPUT => ['pipe', 'w'],
            Crypt_GPG_Engine::FD_ERROR => ['pipe', 'w'],
        ];

        $this->process = proc_open($command, $specs, $this->pipes, null, $env);

        if (!is_resource($this->process)) {
            throw new Crypt_GPG_OpenSubprocessException('Unable to open GPG subprocess.', 0, $command);
        }

        // Set streams as non-blocking
        foreach ($this->pipes as $pipe) {
            stream_set_blocking($pipe, 0);
            stream_set_write_buffer($pipe, 0);
            stream_set_read_buffer($pipe, 0);
        }

        $this->_read([], ['keyedit.prompt']);

        if (feof($this->pipes[Crypt_GPG_Engine::FD_ERROR])) {
            $this->_close();
            throw new Crypt_GPG_OpenSubprocessException('Failed to open GPG subprocess (key not found?).', 0, $command);
        }

        return $this;
    }

    /**
     * Add a user identity to a key (`adduid`).
     *
     * @return Crypt_GPG_KeyEditor The current object, for fluent interface.
     */
    public function addUserId(Crypt_GPG_UserId $userid)
    {
        $handlers = [
            'keygen.name' => $userid->getName(),
            'keygen.email' => $userid->getEmail(),
            'keygen.comment' => $userid->getComment(),
            'passphrase.enter' => $this->passphrase,
        ];

        $this->_write('adduid')->_read($handlers, ['keyedit.prompt']);

        return $this;
    }

    /**
     * Delete a user identity from a key (`deluid`).
     *
     * @return Crypt_GPG_KeyEditor The current object, for fluent interface.
     */
    public function deleteUserId(Crypt_GPG_UserId $userid)
    {
        // TODO: Find the identity index (`uid 0`), call `uid X`, call `deluid`.
        return $this;
    }

    /**
     * Quit the current editing session without saving changes (`quit`).
     *
     * @return Crypt_GPG_KeyEditor The current object, for fluent interface.
     */
    public function quit()
    {
        $this->_write('quit')->_read(['keyedit.save.okay' => 'N']);
        $this->_close();
        return $this;
    }

    /**
     * Save the changes and exit (`save`).
     *
     * @return Crypt_GPG_KeyEditor The current object, for fluent interface.
     */
    public function save()
    {
        $this->_write('save')->_read();
        $this->_close();
        return $this;
    }

    /**
     * Close the process
     */
    private function _close()
    {
        foreach ($this->pipes as $pipe) {
            fflush($pipe);
            fclose($pipe);
        }

        if ($this->process) {
            proc_close($this->process);

            $this->_debug("CLOSED GPG SUBPROCESS");
        }

        $this->process = null;
        $this->pipes = [];
    }

    /**
     * Read process output
     */
    private function _read($handlers = [], $stop_at = [])
    {
        $output = '';
        $passInput = false;

        while (true) {
            $inputStreams = [];
            $outputStreams = [];
            $exceptionStreams = [];

            if (!feof($this->pipes[Crypt_GPG_Engine::FD_ERROR])) {
                $inputStreams[] = $this->pipes[Crypt_GPG_Engine::FD_ERROR];
            }

            if (count($inputStreams) === 0) {
                break;
            }
            
            $ready = stream_select($inputStreams, $outputStreams, $exceptionStreams, null);

            if ($ready === false || $ready === 0) {
                throw new Crypt_GPG_Exception('Error selecting stream for communication with GPG subprocess');
            }

            if (in_array($this->pipes[Crypt_GPG_Engine::FD_ERROR], $inputStreams, true)) {
                $line = fgets($this->pipes[Crypt_GPG_Engine::FD_ERROR], 8192);
                if ($line === false) {
                    break;
                }

                $this->_debug(rtrim("> $line"));

                $output .= $line;

                if (preg_match('/(GET_LINE|GET_HIDDEN|GET_BOOL) ([a-z.]+)/', $line, $matches)) {
                    $token = $matches[2];

                    if (isset($handlers[$token])) {
                        if (is_string($handlers[$token])) {
                            $this->_write($handlers[$token]);
                        } elseif (is_callable($handlers[$token])) {
                            $handlers[$token]($token, $output);
                        }

                        $output = '';
                    }

                    if (in_array($token, $stop_at)) {
                        break;
                    }

                    $passInput = $token == 'passphrase.enter';
                }

                if ($passInput && strpos($line, 'Bad passphrase')) {
                    $this->_close();
                    throw new  Crypt_GPG_BadPassphraseException('Missing or wrong key passphrase');
                }
            }

            usleep(10);
        }

        return $output;
    }

    /**
     * Write to the process input
     */
    private function _write($input)
    {
        $this->_debug("< $input");

        fwrite($this->pipes[Crypt_GPG_Engine::FD_INPUT], "$input\n");
        fflush($this->pipes[Crypt_GPG_Engine::FD_INPUT]);

        return $this;
    }

    /**
     * Log debug information
     */
    private function _debug($line)
    {
        if (!empty($this->options['debug'])) {
            call_user_func($this->options['debug'], $line);
        }
    }
}
