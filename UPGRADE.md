# UPGRADING TO v2

## Dropped support for PHP < 8.1

## Dropped support for GNUPG < 2.2.0

- A lot of code has been removed including the dummy pinentry implementation.
- Removed configuration options: `agent`, `gpgconf`.

## Dropped PEAR dependency

All exceptions thrown by the library now do not inherit from `PEAR_Exception` anymore.
The release channel is now only the Packagist.

## PSR-4

Implemented PSR-4 class structure and autoloading.

- Removed `Crypt_GPGAbstract` class. Common code moved to `Crypt\GPG` class.
- Removed `Crypt_GPG_ProcessControl`
- Renamed classes:
    - `Crypt_GPG` -> `Crypt\GPG`
    - `Crypt_GPG_Engine` -> `Crypt\GPG\Engine`
    - `Crypt_GPG_Key` -> `Crypt\GPG\Key`
    and so on, for exceptions:
    - `Crypt_GPG_Exception` -> `Crypt\GPG\Exceptions\Exception`
    - `Crypt_GPG_BadPassphraseException` -> `Crypt\GPG\Exceptions\BadPassphraseException`
    and so on.

## Optimizations

- Use single `--list-keys` command in place of two `--list-secret-keys` and `--list-public-keys` (#44)
  In case you used command specific options e.g. `$gpg->setEngineOptions(['list-public-keys' => '--with-sig-list'])`,
  you'll have to change it to use `list-keys` key.

- Some methods that have "key identifier" input argument now accept `Key` object. If a `Key` or full fingerprint
  string is provided the `--list-keys` call (that resolved the input into a fingerprint) may be skipped.