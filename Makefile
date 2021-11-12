all:
	cc -o vanity ssh-keygen-ed25519-vanity.c -lsodium

clean:
	rm vanity
