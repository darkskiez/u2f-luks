# U2F LUKS Support - use tokens to unlock encrypted disks.

Disclaimer: This is potentially a very silly / dangerous / risky thing to do.

1. Enroll the token and add the key to the disk
KEYFILE=$(mktemp)
u2f-luks -v enroll >$KEYFILE
cryptsetup luksAddKey /dev/sdxx $KEYFILE
rm $KEYFILE

2. Add initramfs hook script
cp initramfs-hooks/u2fkey /etc/initramfs-tools/hooks/

3. Add keyscript setting, eg:
$EDITOR /etc/crypttab
sdax_crypt UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx none luks,initramfs,keyscript=/usr/local/bin/u2f-luks

4. Update initramfs
update-initramfs -u

