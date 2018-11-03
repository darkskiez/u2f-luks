# U2F LUKS Support - use tokens to unlock encrypted disks.

Disclaimer: This is potentially a very silly / dangerous / risky thing to do.

## Prerequistes

* A configured LUKS encrypted disk.
* A willingness to use non-audited code for your security.
* One or more U2F Tokens

## Build

go build u2f-luks.go

## Install

sudo cp u2f-luks /usr/local/bin
sudo cp initramfs-hooks/u2fkey /etc/initramfs-tools/hooks/

## Enroll a token

1. Generate a new key
KEY=$(mktemp)
u2f-luks -v -enroll -keyfile u2f-luks.keys >$KEY
sudo cryptsetup luksAddKey /dev/sdxx $KEY
sudo mv u2f-luks.keys /etc
rm $KEY

2. Add keyscript setting, eg:
$EDITOR /etc/crypttab
sdax_crypt UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx none luks,initramfs,keyscript=/usr/local/bin/u2f-luks

3. Update initramfs
update-initramfs -u

