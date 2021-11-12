#include <sodium.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

static const unsigned char base64_table[65] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2019, Jouni Malinen <j@w1.fi>
 * This software may be distributed under the terms of the BSD license.
 * https://cgit.freebsd.org/src/tree/contrib/wpa/src/utils/base64.c
 *
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of encoded data
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
uint8_t * base64_encode(const uint8_t *src, size_t len, size_t *out_len) {
  uint8_t *out, *pos;
  const uint8_t *end, *in;
  size_t olen;

  olen = len * 4; // number of bytes needed
  olen = (olen / 3) + (olen % 3 != 0); // number of 3-byte slots needed, rounded up
  olen++; // nul terminator for string
  out = malloc(olen);

  end = src + len;
  in = src;
  pos = out;
  while (end - in >= 3) {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
  }

  if (end - in) {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    } else {
      *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
  }

  *pos = '\0';
  *out_len = pos - out;
  return out;
}

#define PKI1 62  // public key first index
#define PKI2 125 // public key second index
#define SKI  161 // private key index
#define MLEN 19  // metadata length
#define PK_LEN 32
#define SK_LEN 234
#define CHECK "\xf0\xca\xcc\x1a" // 0xf0cacc1a
#define META "\x00\x00\x00\x0b" "ssh-ed25519" "\x00\x00\x00\x20"
#define KEY_PLACEHOLDER "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

static uint8_t SK[SK_LEN] =
  "openssh-key-v1\x00"      // magic string with NUL
  "\x00\x00\x00\x04" "none" // cipher length and value
  "\x00\x00\x00\x04" "none" // kdfname length and value
  "\x00\x00\x00\x00"        // no kdfoptions
  "\x00\x00\x00\x01"        // one (1) public key
  "\x00\x00\x00\x33"        // public key and metadata length (51 bytes)
  META                      // public key
  KEY_PLACEHOLDER           // PKI1 points here
  "\x00\x00\x00\x88"        // remaining length (136 bytes)
  CHECK CHECK               // two 4-byte check values
  META                      // public key (again)
  KEY_PLACEHOLDER           // PKI2 points here
  "\x00\x00\x00\x40"        // private key length (64 bytes)
  KEY_PLACEHOLDER           // SKI points here
  KEY_PLACEHOLDER           // public key part of private key
  "\x00\x00\x00\x00"        // no comments
  "\x01\x02\x03\x04\x05";   // padding

int main(int argc, char* argv[]) {
  if (sodium_init() < 0) return -1;

  const char* substring = argv[1] ? argv[1] : "";
  uint8_t* pk_base64;
  uint8_t* sk_base64;
  size_t pk_base64_len = 0;
  size_t sk_base64_len = 0;
  char* found = NULL;

  while (!found) {
    crypto_sign_ed25519_keypair(SK + PKI1, SK + SKI);
    pk_base64 = base64_encode(SK + PKI1 - MLEN, MLEN + PK_LEN, &pk_base64_len);
    found = strstr(pk_base64, substring);

    if (found) {
      memcpy(SK + PKI2, SK + PKI1, PK_LEN);
      sk_base64 = base64_encode(SK, SK_LEN, &sk_base64_len);
      printf("ssh-ed25519 %.*s\n", pk_base64_len, pk_base64);
      printf("-----BEGIN OPENSSH PRIVATE KEY-----\n");
      printf("%.*s\n", sk_base64_len, sk_base64);
      printf("-----END OPENSSH PRIVATE KEY-----\n");
      free(sk_base64);
    }

    free(pk_base64);
  }
}
