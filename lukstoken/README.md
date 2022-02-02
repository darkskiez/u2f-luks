
# Install

    # Check path is good and support is present
    /sbin/cryptsetup --help|grep "token plugin path"

    # Install the admin tool (u2f-luks/lukstoken/cryptsetup-u2f)
    git clone http://github.com/darkskiez/u2f-luks
    cd u2f-luks/lukstoken/cryptsetup-u2f
    go install

    # Install the plugin (u2f-luks/lukstoken/plugin)
    cd ../plugin 
    make
    cp libcrypt-token-u2f.so /lib/x86_64-linux-gnu/cryptsetup/libcryptsetup-token-u2f.so

    # Register a token with a pin/password
    cryptsetup-u2f -2 -d /path/to/luksdevice

    # Register a token with presense only
    cryptsetup-u2f -d /path/to/luksdevice

    # Open a device (token-only is required if pin/password is set)
    cryptsetup open --type luks --token-only /path/to/luksdevice devicename
   
    # Close a device
    dmsetup remove /dev/mapper/devicename

    # Remove a token
    cryptsetup token remove --token-id=0 /path/to/luksdevice


# Development notes

    fallocate -l 100M testcontainer
    cryptsetup luksFormat testcontainer 
    cryptsetup luksDump --dump-json-metadata testcontainer
    cryptsetup open --type luks --token-only ./testcontainer testcontainer
    dmsetup remove /dev/mapper/testcontainer 
    cryptsetup token remove --token-id=0 testcontainer
