# UPGRADING TO v2

## Dropped support for GNUPG < 2.2.0

A lot of code has been removed including the dummy pinentry implementation.
No change is required for the library users.

## Dropped PEAR dependency

All exceptions thrown by the library now do not inherit from `PEAR_Exception` anymore.
