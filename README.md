# dnstt-crypto

Small C cryptographic helper intended for the Lua DNSTT client on OpenWrt.

## Status

Work in progress. The initial implementation is not yet a validated DNSTT-compatible
cryptographic backend. Do not use it for production traffic until all test vectors,
cross-builds, and interoperability tests pass.

## Design

- Standalone C API and hex-oriented command-line interface.
- BLAKE2s-256 is implemented locally (RFC 7693).
- HMAC-BLAKE2s and HKDF-BLAKE2s are built on that hash implementation.
- X25519 and ChaCha20-Poly1305 use OpenSSL 3 through runtime symbol loading.
- On OpenWrt/musl, `dlopen()` is provided by the C runtime, so no `-ldl` or
  OpenSSL development package is needed at link time.
- Runtime X25519/AEAD operations require `libcrypto.so.3`.

## Build

```sh
make
make test
```

For a cross compiler:

```sh
make clean
make CROSS_COMPILE=mipsel-openwrt-linux-musl-
```

The cross compiler must target the ABI of the destination OpenWrt image. This
example is illustrative; use the exact compiler prefix from the matching SDK.

## CLI

All binary inputs and outputs are lowercase/uppercase-insensitive hexadecimal.
The CLI writes raw result bytes as hex to stdout and diagnostics to stderr.

```sh
dnstt-crypto blake2s HEX
dnstt-crypto hmac-blake2s KEYHEX DATAHEX
dnstt-crypto hkdf-blake2s IKMHEX SALTHEX INFOHEX LENGTH
dnstt-crypto x25519-public PRIVATEHEX
dnstt-crypto x25519 PRIVATEHEX PEER_PUBLICHEX
dnstt-crypto aead-encrypt KEYHEX NONCEHEX AADHEX PLAINTEXTHEX
dnstt-crypto aead-decrypt KEYHEX NONCEHEX AADHEX CIPHERTEXTHEX TAGHEX
```

For AEAD encryption, stdout contains two lines: ciphertext then the 16-byte tag.
For decryption, plaintext is printed only after tag verification succeeds.

## API

See `include/dnstt_crypto.h`.

## Security notes

- Callers must keep private keys and intermediate secrets out of logs.
- The decrypt API clears the output buffer on authentication failure.
- The current OpenSSL symbol loader is intended for serialized calls (as in a
  single Lua state); concurrent first-time initialization is not synchronized.
- The Lua caller must not consume plaintext unless the decrypt function succeeds.
- The helper currently accepts hex through argv; avoid passing secrets on shared
  multi-user systems where process arguments may be observable.
