libcrypt-token-u2f.so: main.go cryptsetup_token.map
	CGO_LDFLAGS_ALLOW='-Wl,--version-script=.*' go build -x -buildmode c-shared -o libcrypt-token-u2f.so
