fallocate -l 100M testcontainer
cryptsetup luksFormat testcontainer 
cryptsetup token import --json-file=testfile.json  testcontainer 

