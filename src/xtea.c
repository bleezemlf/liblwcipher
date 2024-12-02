#include "xtea.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void lw_xtea_init(lw_xtea_context *ctx)
{
    memset(ctx, 0, sizeof(lw_xtea_context));
}

void lw_xtea_free(lw_xtea_context *ctx)
{
    memset(ctx, 0, sizeof(lw_xtea_context));
}

int lw_xtea_setkey(lw_xtea_context *ctx, const uint8_t key[16], unsigned int key_bitlen)
{
    memcpy(ctx->key, key, 16);
    return 0;
}

int lw_xtea_crypt_ecb(lw_xtea_context *ctx, int mode, const uint8_t input[8],
                      uint8_t output[8])
{
    if(mode != XTEA_ENCRYPT && mode != XTEA_DECRYPT) {
        return LW_ERR_XTEA_BAD_INPUT_DATA;
    }
    uint32_t i, num_rounds, v0, v1, sum, delta, k0, k1, k2, k3;
    num_rounds = 64;
    delta = 0x9E3779B9;

    memcpy(&v0, input + 0, 4);
    memcpy(&v1, input + 4, 4);

    if (mode == XTEA_ENCRYPT) {
        sum = 0;
        for (i = 0; i < num_rounds; i++) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ctx->key[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ctx->key[sum >> 11 & 3]);
        }
    } else { /* decrypt */
        sum = delta * num_rounds;
        for (i = 0; i < num_rounds; i++) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + ctx->key[sum >> 11 & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + ctx->key[sum & 3]);
        }
    }
    memcpy(output + 0, &v0, 4);
    memcpy(output + 4, &v1, 4);
    return 0;
}

int lw_xtea_crypt_cbc(lw_xtea_context *ctx, int mode, size_t length, uint8_t iv[8], const uint8_t *input, uint8_t *output)
{
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char temp[8];

    if (mode != XTEA_ENCRYPT && mode != XTEA_DECRYPT) {
        return LW_ERR_XTEA_BAD_INPUT_DATA;
    }

    /* Nothing to do if length is zero. */
    if (length == 0) {
        return 0;
    }

    if (length % 8) {
        return LW_ERR_XTEA_INVALID_INPUT_LENGTH;
    }

    const unsigned char *ivp = iv;

    if (mode == XTEA_DECRYPT) {
        while (length > 0) {
            memcpy(temp, input, 8);
            ret = lw_xtea_crypt_ecb(ctx, mode, input, output);
            if (ret != 0) {
                return ret;
            }
            for (int i = 0; i < 8; i++) {
                output[i] = iv[i] ^ output[i];
            }

            memcpy(iv, temp, 16);

            input += 8;
            output += 8;
            length -= 8;
        }
    } else {
        while (length > 0) {
            for (int i = 0; i < 8; i++) {
                output[i] = ivp[i] ^ input[i];
            }

            ret = lw_xtea_crypt_ecb(ctx, mode, output, output);
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

int lw_xtea_crypt_ctr(lw_xtea_context *ctx, size_t length, uint8_t *nc_off, uint8_t nonce_counter[8],
                      uint8_t stream_block[8],
                      const uint8_t *input, uint8_t *output)
{
    int c, i;
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;

    n = *nc_off;

    if (n > 0b0111) {
        return LW_ERR_XTEA_BAD_INPUT_DATA;
    }

    while (length--) {
        if (n == 0) {
            ret = lw_xtea_crypt_ecb(ctx, XTEA_ENCRYPT, nonce_counter, stream_block);
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

int lw_xtea_self_test(int verbose)
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

    lw_xtea_context ctx;
    lw_xtea_init(&ctx);
    lw_xtea_setkey(&ctx, key, 128);
    lw_xtea_crypt_ecb(&ctx, XTEA_ENCRYPT, plaintext, cipher_buffer);
    lw_xtea_crypt_ecb(&ctx, XTEA_DECRYPT, cipher_buffer, dec_plain_buffer);
    lw_xtea_crypt_ecb(&ctx, XTEA_ENCRYPT, plaintext + 8, cipher_buffer + 8);
    lw_xtea_crypt_ecb(&ctx, XTEA_DECRYPT, cipher_buffer + 8, dec_plain_buffer + 8);
    lw_xtea_crypt_ecb(&ctx, XTEA_ENCRYPT, plaintext + 16, cipher_buffer + 16);
    lw_xtea_crypt_ecb(&ctx, XTEA_DECRYPT, cipher_buffer + 16, dec_plain_buffer + 16);
    lw_xtea_crypt_ecb(&ctx, XTEA_ENCRYPT, plaintext + 24, cipher_buffer + 24);
    lw_xtea_crypt_ecb(&ctx, XTEA_DECRYPT, cipher_buffer + 24, dec_plain_buffer + 24);
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    if (ret != 0) {
        printf("xtea self test ecb failed\n");
        return ret;
    } else {
        printf("xtea self test ecb passed\n");
    }

    lw_xtea_init(&ctx);
    lw_xtea_setkey(&ctx, key, 128);
    lw_xtea_crypt_cbc(&ctx, XTEA_ENCRYPT, 32, iv, plaintext, cipher_buffer);
    memset(iv, 0, 8);
    lw_xtea_crypt_cbc(&ctx, XTEA_DECRYPT, 32, iv, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    if (ret != 0) {
        printf("xtea self test cbc failed\n");
        return ret;
    } else {
        printf("xtea self test cbc passed\n");
    }

    lw_xtea_init(&ctx);
    lw_xtea_setkey(&ctx, key, 128);
    uint8_t nc_off = 0;
    unsigned char stream_block[8] = {0};
    unsigned char nonce_counter_for_enc[8] = {0};
    memcpy(nonce_counter_for_enc, nonce_counter, 8);
    lw_xtea_crypt_ctr(&ctx, 32, &nc_off, nonce_counter_for_enc, stream_block, plaintext, cipher_buffer);
    nc_off = 0;
    lw_xtea_crypt_ctr(&ctx, 32, &nc_off, nonce_counter, stream_block, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    if (ret != 0) {
        printf("xtea self test ctr failed\n");
        return ret;
    } else {
        printf("xtea self test ctr passed\n");
    }

    return ret;
}