#include "xxtea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void lw_xxtea_init(lw_xxtea_context *ctx)
{
    memset(ctx, 0, sizeof(lw_xxtea_context));
}

void lw_xxtea_free(lw_xxtea_context *ctx)
{
    memset(ctx, 0, sizeof(lw_xxtea_context));
}

int lw_xxtea_setkey(lw_xxtea_context *ctx, const uint8_t key[16], unsigned int key_bitlen)
{
    memcpy(ctx->key, key, 16);
    return 0;
}

int lw_xxtea_crypt_ecb(lw_xxtea_context *ctx, int mode, const uint8_t input[8], uint8_t output[8])
{
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
    uint32_t v[2];
    memcpy(v, input, 8);
    int n = 2;
    uint32_t *key = ctx->key;
//    void btea(uint32_t *v, int n, uint32_t const key[4])
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (mode == XXTEA_ENCRYPT) {          /* Coding Part */
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++) {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    } else if (mode == XXTEA_DECRYPT) {  /* Decoding Part */
        // n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
    memcpy(output, v, 8);
    return 0;
}

int lw_xxtea_crypt_cbc(lw_xxtea_context *ctx, int mode, size_t length, uint8_t iv[8], const uint8_t *input, uint8_t *output)
{
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char temp[8];
    if (mode != XXTEA_ENCRYPT && mode != XXTEA_DECRYPT) {
        return LW_ERR_XXTEA_BAD_INPUT_DATA;
    }
    /* Nothing to do if length is zero. */
    if (length == 0) {
        return 0;
    }
    if (length % 8) {
        return LW_ERR_XXTEA_INVALID_INPUT_LENGTH;
    }
    const unsigned char *ivp = iv;
    if (mode == XXTEA_DECRYPT) {
        while (length > 0) {
            memcpy(temp, input, 8);
            ret = lw_xxtea_crypt_ecb(ctx, mode, input, output);
            if (ret != 0) {
                return ret;
            }
            for (int i = 0; i < 8; i++) {
                output[i] = iv[i] ^ output[i];
            }
            memcpy(iv, temp, 8);
            input += 8;
            output += 8;
            length -= 8;
        }
    } else {
        while (length > 0) {
            for (int i = 0; i < 8; i++) {
                output[i] = ivp[i] ^ input[i];
            }
            ret = lw_xxtea_crypt_ecb(ctx, mode, output, output);
            if (ret != 0) {
                return ret;
            }
            ivp = output;
            input += 8;
            output += 8;
            length -= 8;
        }
        memcpy(iv, ivp, 8);
    }
    ret = 0;
    return ret;
}

int lw_xxtea_crypt_ctr(lw_xxtea_context *ctx, size_t length, uint8_t *nc_off, uint8_t nonce_counter[8],
                       uint8_t stream_block[8],
                       const uint8_t *input, uint8_t *output)
{
    int c, i;
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    n = *nc_off;
    if (n > 0b0111) {
        return LW_ERR_XXTEA_BAD_INPUT_DATA;
    }
    while (length--) {
        if (n == 0) {
            ret = lw_xxtea_crypt_ecb(ctx, XXTEA_ENCRYPT, nonce_counter, stream_block);
            if (ret != 0) {
                return ret;
            }

            for (i = 8; i > 0; i--) {
                if (++nonce_counter[i - 1] != 0) {
                    break;
                }
            }
        }
        c = *input++;
        *output++ = (unsigned char) (c ^ stream_block[n]);
        n = (n + 1) & 0b0111;
    }
    *nc_off = n;
    ret = 0;
    return ret;
}

#define print_hex(buffer, len) \
    for (int i = 0; i < len; i++) { \
        printf("%02x ", buffer[i]); \
    } \
    printf("\n");


int lw_xxtea_self_test(int verbose)
{
    int ret;
    const unsigned char plaintext[32] =
            {0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
             0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4,
             0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
             0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE};
    unsigned char cipher_buffer[32] = {0};
    unsigned char dec_plain_buffer[32] = {0};
    const unsigned char key[8] = {0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58};
    unsigned char iv[8] = {0};
    unsigned char nonce_counter[8] = {0};
    lw_xxtea_context ctx;
    lw_xxtea_init(&ctx);
    lw_xxtea_setkey(&ctx, key, 128);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_ENCRYPT, plaintext, cipher_buffer);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_DECRYPT, cipher_buffer, dec_plain_buffer);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_ENCRYPT, plaintext + 8, cipher_buffer + 8);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_DECRYPT, cipher_buffer + 8, dec_plain_buffer + 8);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_ENCRYPT, plaintext + 16, cipher_buffer + 16);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_DECRYPT, cipher_buffer + 16, dec_plain_buffer + 16);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_ENCRYPT, plaintext + 24, cipher_buffer + 24);
    lw_xxtea_crypt_ecb(&ctx, XXTEA_DECRYPT, cipher_buffer + 24, dec_plain_buffer + 24);
    if (verbose) {
        printf("plaintext:\n");
        print_hex(plaintext, 32);
        printf("cipher_buffer:\n");
        print_hex(cipher_buffer, 32);
        printf("dec_plain_buffer:\n");
        print_hex(dec_plain_buffer, 32);
    }
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    memset(cipher_buffer, 0, 32);
    memset(dec_plain_buffer, 0, 32);
    if (ret != 0) {
        printf("xxtea self test ecb failed\n");
        return ret;
    } else {
        printf("xxtea self test ecb passed\n");
    }
    lw_xxtea_init(&ctx);
    lw_xxtea_setkey(&ctx, key, 128);
    lw_xxtea_crypt_cbc(&ctx, XXTEA_ENCRYPT, 32, iv, plaintext, cipher_buffer);
    memset(iv, 0, 8);
    lw_xxtea_crypt_cbc(&ctx, XXTEA_DECRYPT, 32, iv, cipher_buffer, dec_plain_buffer);
    if (verbose) {
        printf("plaintext:\n");
        print_hex(plaintext, 32);
        printf("cipher_buffer:\n");
        print_hex(cipher_buffer, 32);
        printf("dec_plain_buffer:\n");
        print_hex(dec_plain_buffer, 32);
    }
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    memset(cipher_buffer, 0, 32);
    memset(dec_plain_buffer, 0, 32);
    if (ret != 0) {
        printf("xxtea self test cbc failed\n");
        return ret;
    } else {
        printf("xxtea self test cbc passed\n");
    }
    lw_xxtea_init(&ctx);
    lw_xxtea_setkey(&ctx, key, 128);
    uint8_t nc_off = 0;
    unsigned char stream_block[8] = {0};
    unsigned char nonce_counter_for_enc[8] = {0};
    memcpy(nonce_counter_for_enc, nonce_counter, 8);
    lw_xxtea_crypt_ctr(&ctx, 32, &nc_off, nonce_counter_for_enc, stream_block, plaintext, cipher_buffer);
    nc_off = 0;
    lw_xxtea_crypt_ctr(&ctx, 32, &nc_off, nonce_counter, stream_block, cipher_buffer, dec_plain_buffer);
    if (verbose) {
        printf("plaintext:\n");
        print_hex(plaintext, 32);
        printf("cipher_buffer:\n");
        print_hex(cipher_buffer, 32);
        printf("dec_plain_buffer:\n");
        print_hex(dec_plain_buffer, 32);
    }
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    memset(cipher_buffer, 0, 32);
    memset(dec_plain_buffer, 0, 32);
    if (ret != 0) {
        printf("xxtea self test ctr failed\n");
        return ret;
    } else {
        printf("xxtea self test ctr passed\n");
    }
    return ret;
}
