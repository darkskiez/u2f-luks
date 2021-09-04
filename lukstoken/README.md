
fallocate -l 100M testcontainer
cryptsetup luksFormat testcontainer 
cryptsetup token import --json-file=testfile.json  testcontainer 

make
cp libcrypt-token-fido1.so /lib/x86_64-linux-gnu/cryptsetup/libcryptsetup-token-fido1.so

