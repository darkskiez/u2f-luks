# U2F LUKS Support - Use U2F USB tokens to unlock encrypted disks.

**Disclaimer: This is potentially a very silly / dangerous tool to use**

## NEW: Now a cryptsetup external token provider using official API






















## OLD

## Prerequisites

* A Debian variant system
* An already configured LUKS encrypted disk
* A willingness to use non-audited code for your security or convenience.
* One or more U2F Tokens (with USB HID Support)
* A filesystem that can be mounted in an initramfs

This does NOT yet support systemd because systemd does not support keyscripts,
The workaround is that the initramfs parameter forces your disk to be mounted
in the initramfs, before systemd has started.

## How does this work?

This uses some trickery in order to synthesis a static key from a U2F token
because:

* U2F keys are almost stateless holding only a counter
* U2F keys can only sign requests with ecdsa
* U2F signatures are only over partially supplied data include the counters

This tool uses the public key obtained during the register request as the LUKS
privatekey, and derives the public key back from the authenticate requests
using eliptic curve key recovery (http://github.com/darkskiez/eckr) on the
signatures.

This tool encrypts the keyhandle optionally with the userpassphrase, and stores
it in the u2f-luks.keys file. Only the correct keyhandle, passphrase and U2F
token will yeild the correct key. We store a hash based on the correct key
in the keyfile because the key recovery algorithm returns two candidate keys.

Most U2F tokens will blink if the correct matching password is entered.

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
sudo u2f-luks -v -enroll -keyfile /etc/u2f-luks.keys >$KEY
sudo cryptsetup luksAddKey /dev/sdxx $KEY
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
sudo update-initramfs -u
```

4. Reboot and hope for the best

When prompted for your password enter the 2FA password and tap the token. If you did not
supply a password during enroll, you can just tap the token.

If this fails to unlock your disk, enter your previous disk encryption passphrase and
press enter when prompted to touch your token.

5. Revoke your existing passphrase

This optional step is left as an excercise for the enthusiastic.


## Revoke a token

```shell
KEY=$(mktemp)
sudo u2f-luks -v -keyfile /etc/u2f-luks.keys >$KEY
sudo cryptsetup luksRemoveKey /dev/sdxx $KEY
rm $KEY
```

## Revoke a lost token

```shell
# Check which slots are used, 0 is often the original passphrase and 1..7 the additional keys
sudo cryptsetup luksDump /dev/sdxx
# Kill the slot for the lost token, this checks you still have a valid passphrase after
sudo cryptsetup luksKillSlot /dev/sdxx [0-7]
```

## Uninstall

1. Ensure you have a functioning passphrase that works without a U2F token
```shell
sudo cryptsetup luksOpen --test-passphrase /dev/sdxx
```

2. Restore your crypttab file

Remove the initramfs and keyscript args you added during installation

3. Update the initramfs again.
```shell
sudo update-initramfs -u
```

4. Follow The [Revoke a Token](#revoke-a-token) intructions
