# ssh-keygen-ed25519-vanity

Finds a vanity EdDSA SSH public key (and corresponding private key, of course) by brute force.
Requires `libsodium` to be installed to generate the raw Ed25519 keypair.
Run `make` to compile to executable `vanity`,
then `./vanity <substring>` to find a public key with given substring.
There is also a shell script that does basically the same thing but by actually running `ssh-keygen`,
which is probably slower.

This is already covered by the licence, but once again I am **not** responsible for your use of this code.
Don't @ me.
(You can open an issue if there's any problems, with no guarantee that I'll look at it.)

## Handy commands

```sh
# Pipe public key to <file>.pub and private key to <file>,
# while displaying public key on stdout.
./vanity <substring> | tee >(head -n 1 > <file>.pub) >(tail -n 3 > <file>) | head -n 1
# Generate fingerprint and attempt to find the public keyfile.
ssh-keygen -lf <file>
# Generate public key from private keyfile.
ssh-keygen -yf <file>
```

## OpenSSH Ed25519 private key format

I don't know what the two 4-byte check values are for.
OpenSSH literally generates it just using `arc4random()`,
but doesn't do anything with it except duplicate it.
You can edit the source to use your favourite hex word; I'm using `0xf0cacc1a`.

The blocksize is [probably](https://github.com/openssh/openssh-portable/blob/master/cipher.c#L86) 16,
and for [some reason](https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L3972) the number of padding bytes is total modulo 16.
Since up until just before the padding there are 229 bytes, there are 5 bytes of padding,
which OpenSSH conventionally pads with successive integral values.
This doesn't really make sense to me since 16 doesn't divide 234...

If you decide to add a comment you'll have to change both its declared length
as well as the declared length of the remaining bytes after the first public key,
both of which are currently hardcoded,
_and then_ also recalculate the needed amount of padding.

```
6f70656e7373682d6b65792d7631 00           "openssh-key-v1" with NUL terminator
00000004 6e6f6e65                         cipher  length = 4, cipher  = "none"
00000004 6e6f6e65                         kdfname length = 4, kdfname = "none"
00000000                                  kdfoptions length = 0
00000001                                  public keys = 1
00000033                                  public key length = 4 + 11 + 4 + 32
0000000b 7373682d65643235353139 00000020  key type length = 11, key type = "ssh-ed25519", public key length = 32
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx          public key
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
00000088                                  remaining length = 136
f0cacc1a f0cacc1a                         two 4-byte check values
0000000b 7373682d65643235353139 00000020  repeat public key with metadata
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
00000040                                  private key length = 64
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX          private key
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx          public key part of private key
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
00000000                                  comments length = 0
0102030405                                padding
```

## Rough performance stats

Obviously since it's brute force the times are probabilistic,
but this gives you an idea of how feasible it would be to find your desired number of characters.

| Substring | Time (s) |
| --------- | -------- |
| a         | 0.002    |
| ar        | 0.015    |
| ars       | 0.501    |
| arso      | 3.753    |
| arson     | abandon all hope ye who seek five sequential characters |

## References

* Peter Lyons, [OpenSSH Ed25519 Private Key File Format](https://peterlyons.com/problog/2017/12/openssh-ed25519-private-key-file-format/)
* AJ ONeal, [The OpenSSH Private Key Format](https://coolaj86.com/articles/the-openssh-private-key-format/)
* And of course [openssh/openssh-portable](https://github.com/openssh/openssh-portable), especially [sshkey.c](https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L3947)
