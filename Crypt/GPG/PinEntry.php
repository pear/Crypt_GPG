<?php

class Crypt_GPG_PinEntry
{
	protected $stdin = null;
	protected $stdout = null;
	protected $log = null;
	protected $disconnect = false;

	public function run()
	{
		$this->connect();
		$this->send($this->ok('Crypt_GPG pinentry ready and waiting'));

		while (($line = fgets($this->stdin, 8192)) !== false) {
			$this->parseCommand(substr($line, 0, -1));
			if ($this->disconnect) {
				break;
			}
		}

		$this->disconnect();
	}

	protected function parseCommand($line)
	{
		$this->log('<- ' . $line . "\n");
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
		$this->stdin = fopen('php://stdin', 'rb');
		$this->stdout = fopen('php://stdout', 'wb');
		$this->log = fopen(dirname(__FILE__).'/pinentry-log.txt', 'wb');
	}

	protected function disconnect()
	{
		fflush($this->stdout);
		fclose($this->stdout);
		fclose($this->stdin);
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
		$this->send($this->data('test'));
		$this->send($this->ok());
	}

	protected function getInfo($data)
	{
		$parts = explode(' ', $data, 2);
		$command = reset($parts);

		switch ($command) {
		case 'pid':
			$this->getInfoPid();
			$this->send($this->ok());
			return;
		default:
			$this->send($this->ok());
			return;
		}
	}

	protected function getInfoPid()
	{
		return $this->send($this->data(getmypid()));
	}

	protected function bye()
	{
		$this->send($this->ok('closing connection'));
		$this->disconnect = true;
	}

	protected function reset()
	{
		$this->send($this->ok());
	}

	protected function log($data)
	{
		fwrite($this->log, $data);
		fflush($this->log);
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
		// escape. Only %, \n and \r need to be escaped but other values are
		// allowed to be escaped. See http://www.gnupg.org/documentation/manuals/assuan/Server-responses.html
		$data = rawurlencode($data);

		if (strlen($data) > 1000) {
			// break on multiple lines
		}

		return 'D ' . $data . "\n";
	}

	protected function comment($data)
	{
		if (strlen($data) > 1000) {
			// break on multiple lines
		}

		return '# ' . $data . "\n";
	}

	protected function send($data)
	{
		$this->log('-> ' . $data);
		fwrite($this->stdout, $data);
		fflush($this->stdout);
	}
}

?>
