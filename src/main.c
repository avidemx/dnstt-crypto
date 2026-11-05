#include "dnstt_crypto.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A' + 10);
    return -1;
}

static int unhex(const char *s, unsigned char *out,
                 size_t capacity, size_t *out_len) {
    size_t i, len;

    if (!s || !out || !out_len)
        return -1;

    len = strlen(s);
    if ((len & 1U) != 0 || len / 2 > capacity)
        return -1;

    for (i = 0; i < len / 2; i++) {
        int high = hex_value((unsigned char)s[2 * i]);
        int low = hex_value((unsigned char)s[2 * i + 1]);

        if (high < 0 || low < 0)
            return -1;
        out[i] = (unsigned char)((high << 4) | low);
    }

    *out_len = len / 2;
    return 0;
}

static int parse_length(const char *s, size_t capacity, size_t *out) {
    char *end;
    unsigned long long value;

    if (!s || !*s || !out)
        return -1;

    /* Accept decimal digits only; reject signs and whitespace. */
    {
        const unsigned char *p = (const unsigned char *)s;
        while (*p) {
            if (*p < '0' || *p > '9')
                return -1;
            p++;
        }
    }

    errno = 0;
    value = strtoull(s, &end, 10);
    if (errno == ERANGE || *end != '\0' || value > capacity)
        return -1;

    *out = (size_t)value;
    return 0;
}

static void hexout(const unsigned char *p, size_t n) {
    size_t i;
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    putchar('\n');
}

static void usage(void) {
    fprintf(stderr,
        "Usage:\n"
        "  dnstt-crypto blake2s HEX\n"
        "  dnstt-crypto hmac-blake2s KEYHEX DATAHEX\n"
        "  dnstt-crypto hkdf-blake2s IKMHEX SALTHEX INFOHEX LENGTH\n"
        "  dnstt-crypto x25519-public PRIVATEHEX\n"
        "  dnstt-crypto x25519 PRIVATEHEX PEER_PUBLICHEX\n"
        "  dnstt-crypto aead-encrypt KEYHEX NONCEHEX AADHEX PLAINTEXTHEX\n"
        "  dnstt-crypto aead-decrypt KEYHEX NONCEHEX AADHEX CIPHERTEXTHEX TAGHEX\n");
}

int main(int argc, char **argv) {
    unsigned char a[65536], b[65536], c[65536], d[65536];
    unsigned char out[65552], tag[16];
    size_t al = 0, bl = 0, cl = 0, dl = 0, output_len;
    int rc = -1;

    if (argc < 3) {
        usage();
        return 2;
    }

    if (!strcmp(argv[1], "blake2s") && argc == 3) {
        if (unhex(argv[2], a, sizeof a, &al) == 0)
            rc = dnstt_blake2s(out, a, al);
        if (rc == 0)
            hexout(out, 32);

    } else if (!strcmp(argv[1], "hmac-blake2s") && argc == 4) {
        if (unhex(argv[2], a, sizeof a, &al) == 0 &&
            unhex(argv[3], b, sizeof b, &bl) == 0)
            rc = dnstt_hmac_blake2s(out, a, al, b, bl);
        if (rc == 0)
            hexout(out, 32);

    } else if (!strcmp(argv[1], "hkdf-blake2s") && argc == 6) {
        if (parse_length(argv[5], sizeof out, &output_len) == 0 &&
            unhex(argv[2], a, sizeof a, &al) == 0 &&
            unhex(argv[3], b, sizeof b, &bl) == 0 &&
            unhex(argv[4], c, sizeof c, &cl) == 0)
            rc = dnstt_hkdf_blake2s(out, output_len,
                                   a, al, b, bl, c, cl);
        if (rc == 0)
            hexout(out, output_len);

    } else if (!strcmp(argv[1], "x25519-public") && argc == 3) {
        if (unhex(argv[2], a, sizeof a, &al) == 0 && al == 32)
            rc = dnstt_x25519_public(out, a);
        if (rc == 0)
            hexout(out, 32);

    } else if (!strcmp(argv[1], "x25519") && argc == 4) {
        if (unhex(argv[2], a, sizeof a, &al) == 0 && al == 32 &&
            unhex(argv[3], b, sizeof b, &bl) == 0 && bl == 32)
            rc = dnstt_x25519(out, a, b);
        if (rc == 0)
            hexout(out, 32);

    } else if (!strcmp(argv[1], "aead-encrypt") && argc == 6) {
        if (unhex(argv[2], a, sizeof a, &al) == 0 && al == 32 &&
            unhex(argv[3], b, sizeof b, &bl) == 0 && bl == 12 &&
            unhex(argv[4], c, sizeof c, &cl) == 0 &&
            unhex(argv[5], d, sizeof d, &dl) == 0)
            rc = dnstt_chachapoly_encrypt(out, tag, a, b,
                                           c, cl, d, dl);
        if (rc == 0) {
            hexout(out, dl);
            hexout(tag, sizeof tag);
        }

    } else if (!strcmp(argv[1], "aead-decrypt") && argc == 7) {
        size_t tag_len = 0;
        if (unhex(argv[2], a, sizeof a, &al) == 0 && al == 32 &&
            unhex(argv[3], b, sizeof b, &bl) == 0 && bl == 12 &&
            unhex(argv[4], c, sizeof c, &cl) == 0 &&
            unhex(argv[5], d, sizeof d, &dl) == 0 &&
            unhex(argv[6], tag, sizeof tag, &tag_len) == 0 &&
            tag_len == sizeof tag)
            rc = dnstt_chachapoly_decrypt(out, a, b,
                                           c, cl, d, dl, tag);
        if (rc == 0)
            hexout(out, dl);

    } else {
        usage();
        return 2;
    }

    if (rc != 0) {
        fprintf(stderr, "dnstt-crypto: operation failed\n");
        return 1;
    }
    return 0;
}
