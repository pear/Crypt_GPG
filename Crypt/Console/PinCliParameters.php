<?php

namespace Crypt\Console;

class PinCliParameters
{
    private $verbose;
    private $log;

    public function __construct($verbose = 0, $log = null)
    {
        $this->verbose = $verbose;
        $this->log = $log;
    }

    public function getVerbose()
    {
        return $this->verbose;
    }

    public function getLog()
    {
        return $this->log;
    }
}
