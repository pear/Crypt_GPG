#!/bin/sh
#
# Generates a PHP file containing the keyring state and various PGP data blobs
# required by Crypt_GPG unit tests.
#
# Running this script will require a lot of system entropy. Installing an
# entropy generator like 'randomsound' is recommended.
#
# Copyright (c) 2008 Michael Gauthier
#

HOMEDIR=`pwd`"/test-keyring"
GPG="gpg --homedir $HOMEDIR --no-secmem --no-permission-warning --quiet --no-greeting"
DATA="Hello, Alice! Goodbye, Bob!"

echo "Creating key homedir"
mkdir $HOMEDIR

# create temp files for signing
cp test-file-small $HOMEDIR/clearsigned-data
cp test-file-small $HOMEDIR/detached-signature
cp test-file-small $HOMEDIR/normal-signed-data
cp test-file-small $HOMEDIR/dual-clearsigned-data
cp test-file-small $HOMEDIR/dual-detached-signature
cp test-file-small $HOMEDIR/dual-normal-signed-data

# create temp files for encrypting
cp test-file-medium $HOMEDIR/encrypted-data-file
cp test-file-medium $HOMEDIR/encrypted-data-no-passphrase-file
cp test-file-medium $HOMEDIR/encrypted-data-missing-key-file
cp test-file-medium $HOMEDIR/dual-encrypted-data-file
cp test-file-medium $HOMEDIR/dual-encrypted-data-one-passphrase-file

# BUILDING KEYS

# second-keypair@example.com
echo "Creating first-keypair@example.com"
echo "1
2048
0
First Keypair Test Key
first-keypair@example.com
do not encrypt important data with this key
test1
" | $GPG --command-fd 0 --gen-key

# second-keypair@example.com
echo "Creating second-keypair@example.com"
echo "1
2048
0
Second Keypair Test Key
second-keypair@example.com
do not encrypt important data with this key
test2
" | $GPG --command-fd 0 --gen-key

# public-only@example.com
echo "Creating public-only@example.com"
echo "1
2048
0
Public Only Test Key
public-only@example.com
do not encrypt important data with this key
test
" | $GPG --command-fd 0 --gen-key

# no-passphrase@example.com
echo "Creating no-passphrase@example.com"
echo "1
2048
0
No Passphrase Public and Private Test Key
no-passphrase@example.com
do not encrypt important data with this key

" | $GPG --command-fd 0 --gen-key

# external-public@example.com
echo "Creating external-public@example.com"
echo "1
2048
0
External Public Key
external-public@example.com
do not encrypt important data with this key
test
" | $GPG --command-fd 0 --gen-key

# missing-key@example.com
echo "Creating missing-key@example.com"
echo "1
2048
0
Missing Key
missing-key@example.com
do not encrypt important data with this key
test
" | $GPG --command-fd 0 --gen-key

# DONE BUILDING KEYS

# BUILDING FILES

# encrypted-data.asc
echo "generating encrypted-data.asc"
echo -n $DATA | $GPG \
	--recipient first-keypair@example.com \
	--armor \
	--encrypt > $HOMEDIR/encrypted-data.asc

# normal-signed-data.asc
echo "generating normal-signed-data.asc"
echo "test1" | $GPG \
	--command-fd 0 \
	--armor \
	--local-user first-keypair@example.com \
	--sign $HOMEDIR/normal-signed-data

# clearsigned-data.asc
echo "generating clearsigned-data.asc"
echo "test1" | $GPG \
	--command-fd 0 \
	--armor \
	--local-user first-keypair@example.com \
	--clearsign $HOMEDIR/clearsigned-data

# detached-signature.asc
echo "generating detached-signature.asc"
echo "test1" | $GPG \
	--command-fd 0 \
	--armor \
	--local-user first-keypair@example.com \
	--detach-sign $HOMEDIR/detached-signature

# dual-encrypted-data@example.com
echo "generating dual-encrypted-data.asc"
echo -n $DATA | $GPG \
	--recipient first-keypair@example.com \
	--recipient second-keypair@example.com \
	--armor \
	--encrypt > $HOMEDIR/dual-encrypted-data.asc

# dual-normal-signed-data.asc
echo "generating dual-normal-signed-data.asc"
echo "test1
test2" | $GPG \
	--command-fd 0 \
	--armor \
	--local-user second-keypair@example.com \
	--local-user first-keypair@example.com \
	--sign $HOMEDIR/dual-normal-signed-data

# dual-clearsigned-data.asc
echo "generating dual-clearsigned-data.asc"
echo "test1
test2" | $GPG \
	--command-fd 0 \
	--armor \
	--local-user second-keypair@example.com \
	--local-user first-keypair@example.com \
	--clearsign $HOMEDIR/dual-clearsigned-data

# dual-detached-signature.asc
echo "generating dual-detached-signature.asc"
echo "test1
test2" | $GPG \
	--command-fd 0 \
	--armor \
	--local-user second-keypair@example.com \
	--local-user first-keypair@example.com \
	--detach-sign $HOMEDIR/dual-detached-signature

# public-only-sec.asc
echo "generating public-only-sec.asc"
$GPG \
	--armor \
	--export-secret-keys public-only@example.com > $HOMEDIR/public-only-sec.asc

# public-only-pub.asc
echo "generating public-only-pub.asc"
$GPG \
	--armor \
	--export public-only@example.com > $HOMEDIR/public-only-pub.asc

# delete public-only@example.com secret key
echo "deleting secret key for public-only@example.com"
echo "y" | $GPG \
	--command-fd 0 \
	--delete-secret-key public-only@example.com

# encrypted-data.asc
echo "generating encrypted-data.asc"
echo -n $DATA | $GPG \
	--recipient first-keypair@example.com \
	--armor \
	--encrypt > $HOMEDIR/encrypted-data.asc

# encrypted-data-file.asc
echo "generating encrypted-data-file.asc"
$GPG \
	--recipient first-keypair@example.com \
	--armor \
	--encrypt $HOMEDIR/encrypted-data-file

# encrypted-data-no-passphrase.asc
echo "generating encrypted-data-no-passphrase.asc"
echo -n $DATA | $GPG \
	--recipient no-passphrase@example.com \
	--armor \
	--encrypt > $HOMEDIR/encrypted-data-no-passphrase.asc

# encrypted-data-no-passphrase-file.asc
echo "generating encrypted-data-no-passphrase-file.asc"
$GPG \
	--recipient no-passphrase@example.com \
	--armor \
	--encrypt $HOMEDIR/encrypted-data-no-passphrase-file

# dual-encrypted-data-one-passphrase.asc
echo "generating dual-encrypted-data-one-passphrase.asc"
echo -n $DATA | $GPG \
	--recipient first-keypair@example.com \
	--recipient no-passphrase@example.com \
	--armor \
	--encrypt > $HOMEDIR/dual-encrypted-data-one-passphrase.asc

# dual-encrypted-data-one-passphrase-file.asc
echo "generating dual-encrypted-data-one-passphrase-file.asc"
$GPG \
	--recipient first-keypair@example.com \
	--recipient no-passphrase@example.com \
	--armor \
	--encrypt $HOMEDIR/dual-encrypted-data-one-passphrase-file

# delete external-public@example.com secret key
echo "deleting secret key for external-public@example.com"
echo "y" | $GPG \
	--command-fd 0 \
	--delete-secret-key external-public@example.com

# external-public-pub.asc
echo "generating external-public-pub.asc"
$GPG \
	--armor \
	--export external-public@example.com > $HOMEDIR/external-public-pub.asc

# delete external-public@example.com key
echo "deleting key external-public@example.com"
echo "y" | $GPG \
	--command-fd 0 \
	--delete-secret-and-public-key external-public@example.com

# encrypted-data-missing-key.asc
echo "generating encrypted-data-missing-key.asc"
echo -n $DATA | $GPG \
	--recipient missing-key@example.com \
	--armor \
	--encrypt > $HOMEDIR/encrypted-data-missing-key.asc

# encrypted-data-missing-key-file.asc
echo "generating encrypted-data-missing-key-file.asc"
$GPG \
	--recipient missing-key@example.com \
	--armor \
	--encrypt $HOMEDIR/encrypted-data-missing-key-file

# delete missing-key@example.com key
echo "deleting key missing-key@example.com"
echo "y" | $GPG \
	--command-fd 0 \
	--delete-secret-and-public-key missing-key@example.com

# DONE BUILDING FILES

echo "dumping keyring state"
php -f build-keyring.php $HOMEDIR > keyring-dump.php

echo "removing key homedir"
rm -rf $HOMEDIR
