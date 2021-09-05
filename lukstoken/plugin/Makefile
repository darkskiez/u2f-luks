libcrypt-token-u2f.so: main.go cryptsetup_token.map
	CGO_LDFLAGS_ALLOW='.*' go build -x -buildmode c-shared -o libcrypt-token-u2f.so github.com/darkskiez/u2f-luks/lukstoken/plugin

