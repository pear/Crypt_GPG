<?php

namespace Console;

require_once __DIR__ . '/ArrayAccessTrait.php';

class PinCliParameters implements \ArrayAccess
{
    use \Console\ArrayAccessTrait;

    private $verbose = false;
    private $log = null;

    public function __construct($verbose = false, $log = null) {
        $this->verbose = $verbose;
        $this->log = $log;
    }

    public function getVerbose() {
        return $this->verbose;
    }

    public function getLog() {
        return $this->log;
    }
}