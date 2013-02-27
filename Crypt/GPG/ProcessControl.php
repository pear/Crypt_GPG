<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

class Crypt_GPG_ProcessControl
{
    /**
     * @var integer
     */
    protected $pid;

    // {{ __construct()

    public function __construct($pid)
    {
        $this->pid = $pid;
    }

    // }}
    // {{ isRunning()

    public function isRunning()
    {
        $running = false;

        if (PHP_OS === 'WINNT') {
            $command = 'tasklist /fo csv /nh /fi '
                . escapeshellarg('PID eq ' . $this->pid);

            $result  = exec($command);
            $parts   = explode(',', $result);
            $running = (count($parts) > 1 && trim($parts[1], '"') == $this->pid);
        } else {
            $result  = exec('ps -p ' . escapeshellarg($this->pid) . ' -o pid=');
            $running = (trim($result) == $this->pid);
        }

        return $running;
    }

    // }}
    // {{ terminate()

    public function terminate()
    {
        if (function_exists('posix_kill')) {
            posix_kill($this->pid, SIGTERM);
        } elseif (PHP_OS === 'WINNT') {
            exec('taskkill /PID ' . escapeshellarg($this->pid));
        } else {
            exec('kill -15 ' . escapeshellarg($this->pid));
        }
    }

    // }}
}

?>
