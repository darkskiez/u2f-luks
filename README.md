# U2F LUKS Support - use tokens to unlock encrypted disks.

**Disclaimer: This is potentially a very silly / dangerous tool to use**

## Prerequistes

* A Debian variant system
* An already configured LUKS encrypted disk
* A willingness to use non-audited code for your security or convenience.
* One or more U2F Tokens
* A filesystem that can be mounted in an initramfs

This does NOT yet support systemd because systemd does not support keyscripts,
The workaround is that the initramfs parameter forces your disk to be mounted
in the initramfs, before systemd has started.

## Download and Build

`go get -u github.com/darkskiez/u2f-luks`

## Install

```shell
sudo cp $GOPATH/bin/u2f-luks /usr/local/bin
sudo cp $GOPATH/src/github.com/darkskiez/u2f-luks/initramfs-hooks/u2fkey /etc/initramfs-tools/hooks/
```

## Enroll a token

1. Generate a new key
```shell
KEY=$(mktemp)
u2f-luks -v -enroll -keyfile u2f-luks.keys >$KEY
sudo cryptsetup luksAddKey /dev/sdxx $KEY
sudo mv u2f-luks.keys /etc
rm $KEY
```

2. Add initramfs and keyscript setting, eg:
```shell
$EDITOR /etc/crypttab
# OLD
sdax_crypt UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx none luks
# NEW
sdax_crypt UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx none luks,initramfs,keyscript=/usr/local/bin/u2f-luks
```

3. Update initramfs
```shell
update-initramfs -u
```
