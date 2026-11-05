#define _GNU_SOURCE
#include "dnstt_crypto.h"
#include <dlfcn.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

static void *handle;
static EVP_PKEY *(*p_new_raw_private)(void *, const char *, const char *, const unsigned char *, size_t);
static EVP_PKEY *(*p_new_raw_public)(void *, const char *, const char *, const unsigned char *, size_t);
static int (*p_get_raw_public)(const EVP_PKEY *, unsigned char *, size_t *);
static EVP_PKEY_CTX *(*p_pkey_ctx_new)(void *, EVP_PKEY *, const char *);
static int (*p_derive_init)(EVP_PKEY_CTX *);
static int (*p_derive_peer)(EVP_PKEY_CTX *, EVP_PKEY *);
static int (*p_derive)(EVP_PKEY_CTX *, unsigned char *, size_t *);
static void (*p_pkey_free)(EVP_PKEY *);
static void (*p_pkey_ctx_free)(EVP_PKEY_CTX *);
static const EVP_CIPHER *(*p_chacha)(void);
static EVP_CIPHER_CTX *(*p_cipher_ctx_new)(void);
static void (*p_cipher_ctx_free)(EVP_CIPHER_CTX *);
static int (*p_encrypt_init)(EVP_CIPHER_CTX *, const EVP_CIPHER *, void *, const unsigned char *, const unsigned char *);
static int (*p_decrypt_init)(EVP_CIPHER_CTX *, const EVP_CIPHER *, void *, const unsigned char *, const unsigned char *);
static int (*p_cipher_ctrl)(EVP_CIPHER_CTX *, int, int, void *);
static int (*p_encrypt_update)(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int);
static int (*p_decrypt_update)(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int);
static int (*p_encrypt_final)(EVP_CIPHER_CTX *, unsigned char *, int *);
static int (*p_decrypt_final)(EVP_CIPHER_CTX *, unsigned char *, int *);

#define SYM(var, sym) do { \
    *(void **)(&var) = dlsym(h, sym); \
    if (!(var)) goto fail; \
} while (0)

static void clear_crypto_symbols(void) {
    p_new_raw_private = NULL;
    p_new_raw_public = NULL;
    p_get_raw_public = NULL;
    p_pkey_ctx_new = NULL;
    p_derive_init = NULL;
    p_derive_peer = NULL;
    p_derive = NULL;
    p_pkey_free = NULL;
    p_pkey_ctx_free = NULL;
    p_chacha = NULL;
    p_cipher_ctx_new = NULL;
    p_cipher_ctx_free = NULL;
    p_encrypt_init = NULL;
    p_decrypt_init = NULL;
    p_cipher_ctrl = NULL;
    p_encrypt_update = NULL;
    p_decrypt_update = NULL;
    p_encrypt_final = NULL;
    p_decrypt_final = NULL;
}

static int load_crypto(void) {
    void *h;

    if (handle)
        return 0;

    h = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (!h)
        h = dlopen("/usr/lib/libcrypto.so.3", RTLD_NOW | RTLD_LOCAL);
    if (!h)
        return -1;

    SYM(p_new_raw_private, "EVP_PKEY_new_raw_private_key_ex");
    SYM(p_new_raw_public, "EVP_PKEY_new_raw_public_key_ex");
    SYM(p_get_raw_public, "EVP_PKEY_get_raw_public_key");
    SYM(p_pkey_ctx_new, "EVP_PKEY_CTX_new_from_pkey");
    SYM(p_derive_init, "EVP_PKEY_derive_init");
    SYM(p_derive_peer, "EVP_PKEY_derive_set_peer");
    SYM(p_derive, "EVP_PKEY_derive");
    SYM(p_pkey_free, "EVP_PKEY_free");
    SYM(p_pkey_ctx_free, "EVP_PKEY_CTX_free");
    SYM(p_chacha, "EVP_chacha20_poly1305");
    SYM(p_cipher_ctx_new, "EVP_CIPHER_CTX_new");
    SYM(p_cipher_ctx_free, "EVP_CIPHER_CTX_free");
    SYM(p_encrypt_init, "EVP_EncryptInit_ex");
    SYM(p_decrypt_init, "EVP_DecryptInit_ex");
    SYM(p_cipher_ctrl, "EVP_CIPHER_CTX_ctrl");
    SYM(p_encrypt_update, "EVP_EncryptUpdate");
    SYM(p_decrypt_update, "EVP_DecryptUpdate");
    SYM(p_encrypt_final, "EVP_EncryptFinal_ex");
    SYM(p_decrypt_final, "EVP_DecryptFinal_ex");

    /* Publish the handle only after every required symbol is resolved. */
    handle = h;
    return 0;

fail:
    clear_crypto_symbols();
    dlclose(h);
    return -1;
}

int dnstt_x25519_public(uint8_t out[32], const uint8_t priv[32]) {
    EVP_PKEY *k;
    size_t n = 32;
    int rc = -1;

    if (!out || !priv)
        return -1;
    if (load_crypto()) {
        memset(out, 0, 32);
        return -1;
    }

    k = p_new_raw_private(NULL, "X25519", NULL, priv, 32);
    if (!k)
        goto done;

    if (p_get_raw_public(k, out, &n) == 1 && n == 32)
        rc = 0;

    p_pkey_free(k);

done:
    if (rc != 0)
        memset(out, 0, 32);
    return rc;
}

int dnstt_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[32]) {
    EVP_PKEY *a = NULL, *b = NULL;
    EVP_PKEY_CTX *c = NULL;
    size_t n = 32;
    int rc = -1;

    if (!out || !priv || !peer)
        return -1;
    if (load_crypto()) {
        memset(out, 0, 32);
        return -1;
    }

    a = p_new_raw_private(NULL, "X25519", NULL, priv, 32);
    b = p_new_raw_public(NULL, "X25519", NULL, peer, 32);
    if (!a || !b)
        goto done;

    c = p_pkey_ctx_new(NULL, a, NULL);
    if (!c)
        goto done;

    if (p_derive_init(c) != 1 ||
        p_derive_peer(c, b) != 1 ||
        p_derive(c, out, &n) != 1 ||
        n != 32)
        goto done;

    {
        unsigned i;
        uint8_t z = 0;
        for (i = 0; i < 32; i++)
            z |= out[i];
        if (z != 0)
            rc = 0;
    }

done:
    if (c)
        p_pkey_ctx_free(c);
    if (a)
        p_pkey_free(a);
    if (b)
        p_pkey_free(b);
    if (rc != 0)
        memset(out, 0, 32);
    return rc;
}

static int aead(int enc, uint8_t *out, uint8_t tag[16],
                const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t *aad, size_t al,
                const uint8_t *in, size_t il) {
    EVP_CIPHER_CTX *c = NULL;
    int n = 0, total = 0, rc = -1;
    uint8_t finalbuf[16];

    /*
     * On every decryption failure, clear the caller's plaintext buffer,
     * including failures detected before an EVP context is created.
     */
    if (!out || !tag || !key || !nonce ||
        (!aad && al) || (!in && il) ||
        al > INT_MAX || il > INT_MAX) {
        if (!enc && out && il)
            memset(out, 0, il);
        return -1;
    }

    if (load_crypto()) {
        if (!enc && il)
            memset(out, 0, il);
        return -1;
    }

    c = p_cipher_ctx_new();
    if (!c)
        goto done;

    if ((enc ? p_encrypt_init(c, p_chacha(), NULL, NULL, NULL)
             : p_decrypt_init(c, p_chacha(), NULL, NULL, NULL)) != 1)
        goto done;

    if (p_cipher_ctrl(c, 0x9, 12, NULL) != 1)
        goto done;

    if ((enc ? p_encrypt_init(c, NULL, NULL, key, NULL)
             : p_decrypt_init(c, NULL, NULL, key, NULL)) != 1)
        goto done;

    if ((enc ? p_encrypt_init(c, NULL, NULL, NULL, nonce)
             : p_decrypt_init(c, NULL, NULL, NULL, nonce)) != 1)
        goto done;

    if (al) {
        n = 0;
        if ((enc ? p_encrypt_update(c, NULL, &n, aad, (int)al)
                 : p_decrypt_update(c, NULL, &n, aad, (int)al)) != 1)
            goto done;
    }

    /*
     * AAD processing does not contribute to ciphertext/plaintext length.
     * Explicitly reset n so empty payloads are handled correctly.
     */
    n = 0;
    total = 0;

    if (il) {
        if ((enc ? p_encrypt_update(c, out, &n, in, (int)il)
                 : p_decrypt_update(c, out, &n, in, (int)il)) != 1)
            goto done;

        total = n;
    }

    n = 0;

    if (!enc && p_cipher_ctrl(c, 0x11, 16, tag) != 1)
        goto done;

    if ((enc ? p_encrypt_final(c, finalbuf, &n)
             : p_decrypt_final(c, finalbuf, &n)) != 1)
        goto done;

    if (n)
        memcpy(out + total, finalbuf, (size_t)n);
    total += n;

    if (enc && p_cipher_ctrl(c, 0x10, 16, tag) != 1)
        goto done;

    if ((size_t)total != il)
        goto done;

    rc = 0;

done:
    if (c)
        p_cipher_ctx_free(c);
    memset(finalbuf, 0, sizeof finalbuf);
    if (rc != 0 && !enc && out)
        memset(out, 0, il);
    return rc;
}

int dnstt_chachapoly_encrypt(uint8_t *ciphertext, uint8_t tag[16],
                             const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t plaintext_len) {
    return aead(1, ciphertext, tag, key, nonce,
                aad, aad_len, plaintext, plaintext_len);
}

int dnstt_chachapoly_decrypt(uint8_t *plaintext,
                             const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t tag[16]) {
    uint8_t tag_copy[16];

    if (!tag)
        return -1;

    memcpy(tag_copy, tag, sizeof tag_copy);
    return aead(0, plaintext, tag_copy, key, nonce,
                aad, aad_len, ciphertext, ciphertext_len);
}
