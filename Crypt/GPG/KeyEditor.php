<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

require_once 'Crypt/GPGAbstract.php';

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
     * @param array  $options    Additional command line options
     *
     * @return $this The current object, for fluent interface.
     *
     * @sensitive $passphrase
     */
    public function edit($key, $passphrase = null, $options = [])
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

        if (!empty($options)) {
            $arguments = array_merge($arguments, $options);
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
     * @return $this The current object, for fluent interface.
     */
    public function addUserId(Crypt_GPG_UserId $userid)
    {
        $handlers = [
            'keygen.name' => $userid->getName(),
            'keygen.email' => $userid->getEmail(),
            'keygen.comment' => $userid->getComment(),
            'passphrase.enter' => $this->passphrase,
        ];

        $output = $this->_write('adduid')->_read($handlers, ['keyedit.prompt']);

        if (strpos($output, 'Need the secret key to do this')) {
            $this->_close();
            throw new Crypt_GPG_Exception('Failed to add a user. No secret key found.');
        }

        return $this;
    }

    /**
     * Delete a user identity from a key (`deluid`).
     *
     * @param Crypt_GPG_UserId $userid   User identity to delete
     * @param bool             $by_email Delete all identities with specified email address
     *
     * @return $this The current object, for fluent interface.
     */
    public function deleteUserId(Crypt_GPG_UserId $userid, $by_email = false)
    {
        $handlers = [
            'keyedit.remove.uid.okay' => true,
            'passphrase.enter' => $this->passphrase,
        ];

        foreach ($this->_find_users($userid, $by_email) as $uid) {
            $this->_write("uid {$uid}")->_read($handlers, ['keyedit.prompt']);
            $output = $this->_write('deluid')->_read($handlers, ['keyedit.prompt']);

            if (strpos($output, 'You can\'t delete the last')) {
                $this->_close();
                throw new Crypt_GPG_Exception('Failed to delete user from a key. You can\'t delete the last user.');
            }
        }

        return $this;
    }

    /**
     * Set expiration date for a primary key (`expire`).
     *
     * @param string|int $period  Validation period: Either of:
     *                            - 0 or an empty string for no expiration
     *                            - <n>  - expiration in days
     *                            - <n>w - expiration in weeks
     *                            - <n>m - expiration in months
     *                            - <n>y - expiration in years
     *
     * @return $this The current object, for fluent interface.
     */
    public function expire($period = '')
    {
        if ($period === '') {
            $period = '0';
        }

        if (!preg_match('/^[0-9]+[wmy]?$/i', (string) $period)) {
            $this->_close();
            throw new Crypt_GPG_Exception('Failed to set expiration. Invalid period specification.');
        }

        $handlers = [
            'keygen.valid' => (string) $period,
            'passphrase.enter' => $this->passphrase,
        ];

        $this->_write('expire')->_read($handlers, ['keyedit.prompt']);

        return $this;
    }

    /**
     * Change a key passphrase (`passwd`).
     *
     * @param string $passphrase New passphrase
     *
     * @return $this The current object, for fluent interface.
     */
    public function passwd($passphrase)
    {
        // FIXME: Seems old and new pass use the same 'passphrase.enter' command
        // What if the key has no password (or it is in cache)?

        $handlers = [
            'passphrase.enter' => [$this->passphrase, $passphrase],
        ];

        // TODO: This does not seem to work with empty passphrase

        $this->_write('passwd')->_read($handlers, ['keyedit.prompt']);

        return $this;
    }

    /**
     * Revoke a user identity (`revuid`).
     *
     * @param Crypt_GPG_UserId $userid     User identity to delete
     * @param bool             $by_email   Delete all identities with specified email address
     * @param bool             $is_invalid Mark the user as "no longer valid"
     * @param string           $reason     Revocation reason description
     *
     * @return $this The current object, for fluent interface.
     */
    public function revokeUserId(Crypt_GPG_UserId $userid, $by_email = false, $is_invalid = true, $reason = '')
    {
        $handlers = [
            'keyedit.revoke.uid.okay' => true,
            'ask_revocation_reason.code' => $is_invalid ? '4' : '0',
            'ask_revocation_reason.text' => $reason,
            'ask_revocation_reason.okay' => true,
            'passphrase.enter' => $this->passphrase,
        ];

        foreach ($this->_find_users($userid, $by_email) as $uid) {
            $this->_write("uid {$uid}")->_read([], ['keyedit.prompt']);
            $output = $this->_write('revuid')->_read($handlers, ['keyedit.prompt']);

            if (strpos($output, 'Cannot revoke the last valid user')) {
                $this->_close();
                throw new Crypt_GPG_Exception('Failed to revoke the user. You can\'t revoke the last valid user.');
            }
        }

        return $this;
    }

    /**
     * Sign a key.
     *
     * Signing key selection can be done by adding `--local-user=AABBCCDD`
     * to the edit() method `$options` argument.
     *
     * @return $this The current object, for fluent interface.
     */
    public function sign()
    {
        $handlers = [
            'passphrase.enter' => $this->passphrase,
        ];

        $output = $this->_write('sign')->_read($handlers, ['keyedit.prompt']);

        if (preg_match('/signing failed:(.*)/', $output, $matches)) {
            $this->_close();
            throw new Crypt_GPG_Exception('Failed to sign the key. Error: ' . trim($matches[1]));
        }

        return $this;
    }

    /**
     * Quit the current editing session without saving changes (`quit`).
     *
     * @return $this The current object, for fluent interface.
     */
    public function quit()
    {
        $this->_write('quit')->_read(['keyedit.save.okay' => false]);
        $this->_close();
        return $this;
    }

    /**
     * Save the changes and exit (`save`).
     *
     * @return $this The current object, for fluent interface.
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

        $this->passphrase = '';
        $this->process = null;
        $this->pipes = [];
    }

    /**
     * Read process output
     */
    private function _read($handlers = [], $stop_at = [])
    {
        if (empty($this->pipes[Crypt_GPG_Engine::FD_ERROR])) {
            $this->_close();
            throw new Crypt_GPG_Exception('The key editor output stream is closed.');
        }

        $output = '';
        $passInput = false;

        while (true) {
            $inputStreams = [];
            $outputStreams = [];
            $exceptionStreams = [];

            if (!empty($this->pipes[Crypt_GPG_Engine::FD_ERROR]) && !feof($this->pipes[Crypt_GPG_Engine::FD_ERROR])) {
                $inputStreams[] = $this->pipes[Crypt_GPG_Engine::FD_ERROR];
            }

            if (count($inputStreams) === 0) {
                break;
            }

            $ready = stream_select($inputStreams, $outputStreams, $exceptionStreams, null);

            if ($ready === false || $ready === 0) {
                $this->_close();
                throw new Crypt_GPG_Exception('Error selecting stream for communication with GPG subprocess');
            }

            if (in_array($this->pipes[Crypt_GPG_Engine::FD_ERROR], $inputStreams, true)) {
                $line = fgets($this->pipes[Crypt_GPG_Engine::FD_ERROR], 8192);
                if ($line === false) {
                    break;
                }

                $this->_debug(rtrim("> $line"));

                $output .= $line;

                if (preg_match('/(GET_LINE|GET_HIDDEN|GET_BOOL) ([a-z._]+)/', $line, $matches)) {
                    $token = $matches[2];

                    if (isset($handlers[$token])) {
                        $handler = $handlers[$token];
                        if (is_array($handler)) {
                            $handler = array_shift($handlers[$token]);
                        }

                        if (is_string($handler)) {
                            $this->_write($handler);
                        } elseif (is_bool($handler)) {
                            $this->_write($handler ? 'y' : 'N');
                        } elseif (is_callable($handler)) {
                            $handler($token, $output);
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
        if (empty($this->pipes[Crypt_GPG_Engine::FD_INPUT]) || feof($this->pipes[Crypt_GPG_Engine::FD_INPUT])) {
            throw new Crypt_GPG_Exception('The key editor input stream is closed.');
        }

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

    /**
     * Find user identities in the key (by full identity or email)
     */
    private function _find_users(Crypt_GPG_UserId $userid, $by_email = false)
    {
        $output = $this->_write('list')->_read([], ['keyedit.prompt']);

        // Process the list output to find and match the user entries, and get their ids
        $uids = [];
        foreach (explode("\n", $output) as $line) {
            if (preg_match('/^\[[^\]]+\]\s+\(([0-9]+)\)\.?\s+(.*)$/', $line, $matches)) {
                $ident = Crypt_GPG_UserId::parse($matches[2]);
                if ((string) $ident === (string) $userid || ($by_email && $ident->getEmail() === $userid->getEmail())) {
                    $uids[] = $matches[1];
                }
            }
        }

        if (empty($uids)) {
            throw new Crypt_GPG_Exception("No matching users in the key.");
        }

        // We'll delete users in order where deletion does not change other IDs
        arsort($uids, SORT_NUMERIC);

        return $uids;
    }
}
