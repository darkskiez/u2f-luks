
# Install

# Check path is good
/sbin/cryptsetup --help|grep "token plugin path"

cd plugin
make
cp libcrypt-token-u2f.so /lib/x86_64-linux-gnu/cryptsetup/libcryptsetup-token-u2f.so

# Development notes

fallocate -l 100M testcontainer
cryptsetup luksFormat testcontainer 
cryptsetup token import --json-file=testfile.json testcontainer 
cryptsetup luksDump --dump-json-metadata testcontainer
cryptsetup luksOpen --token-only ./testcontainer testcontainer 

dmsetup remove /dev/mapper/testcontainer 
cryptsetup token remove --token-id=0 testcontainer 



