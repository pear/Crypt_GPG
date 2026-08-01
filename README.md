# Crypt_GPG #

Crypt_GPG is a PHP package to interact with the [GNU Privacy Guard
(GnuPG)](https://www.gnupg.org/). GnuPG is a free and open-source
implementation of the [OpenPGP](https://www.ietf.org/rfc/rfc4880.txt)
protocol, providing key management, data encryption and data signing.
Crypt_GPG provides an object-oriented API for performing OpenPGP
actions using GnuPG.

## Documentation ##

## Installing ##
To install from scratch
`$ composer require pear/crypt_gpg`

## Testing ##
To test, run either
`$ vendor/bin/phpunit tests`

### Quick Example
```php
<?php

use Crypt/GPG;

$gpg = new GPG();
$gpg->addEncryptKey('test@example.com');
$data = $gpg->encrypt('my secret data');

?>
```
