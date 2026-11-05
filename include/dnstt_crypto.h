#ifndef DNSTT_CRYPTO_H
#define DNSTT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define DNSTT_CRYPTO_OK 0
#define DNSTT_CRYPTO_ERR -1

int dnstt_blake2s(uint8_t out[32], const void *data, size_t len);
int dnstt_hmac_blake2s(uint8_t out[32], const void *key, size_t key_len,
                       const void *data, size_t data_len);
int dnstt_hkdf_blake2s(uint8_t *out, size_t out_len,
                       const void *ikm, size_t ikm_len,
                       const void *salt, size_t salt_len,
                       const void *info, size_t info_len);
int dnstt_x25519_public(uint8_t out[32], const uint8_t private_key[32]);
int dnstt_x25519(uint8_t out[32], const uint8_t private_key[32],
                 const uint8_t peer_public_key[32]);
int dnstt_chachapoly_encrypt(uint8_t *ciphertext, uint8_t tag[16],
                 const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plaintext, size_t plaintext_len);
int dnstt_chachapoly_decrypt(uint8_t *plaintext,
                 const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ciphertext, size_t ciphertext_len,
                 const uint8_t tag[16]);

#endif
