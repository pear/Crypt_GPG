# Crypt_GPG #

Crypt_GPG is a PHP package to interact with the [GNU Privacy Guard
(GnuPG)](https://www.gnupg.org/). GnuPG is a free and open-source
implementation of the [OpenPGP](https://www.ietf.org/rfc/rfc4880.txt)
protocol, providing key management, data encryption and data signing.
Crypt_GPG provides an object-oriented API for performing OpenPGP
actions using GnuPG.

## Documentation ##

## Installing ##
To install using [Composer](https://getcomposer.org)
```
$ composer require pear/crypt_gpg
```

## Testing ##
To test, run
```
$ vendor/bin/phpunit tests
```

### Quick Example
```php
<?php

use Crypt/GPG;

$gpg = new GPG([
        'homedir' => '/home/alec',
        'binary' => '/usr/bin/gpg',
]);

$gpg->addEncryptKey('test@example.com');
$data = $gpg->encrypt('my secret data');

?>
```
The `GPG` is the main class that provides most of the API. It will return data using
`Key`, `SubKey`, `UserId`, `Signature` objects.

Additionally you can use `KeyEditor` or `KeyGenerator` for functionality not covered by `GPG`.

### Key Generation
```php
<?php

use Crypt/GPG/KeyGenerator;

$keygen = new KeyGenerator([
        'homedir' => '/home/alec',
        'binary' => '/usr/bin/gpg',
]);

$key = $keygen->generateKey('Test Keypair');

?>
```
