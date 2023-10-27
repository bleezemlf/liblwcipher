#include "present.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUNDS               32
#define ROUND_KEY_SIZE_BYTES  8
#define PRESENT_BLOCK_SIZE_BYTES 8
// In reality, if you want to use 128 bit present, you should probably just use aes...

unsigned char sBox[16] = {
        0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};

unsigned char sBoxInverse[16] = {
        0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA};

void lw_present_init(lw_present_context *ctx)
{
    memset(ctx, 0, sizeof(lw_present_context));
}

void lw_present_free(lw_present_context *ctx)
{
    memset(ctx, 0, sizeof(lw_present_context));
}

int lw_present_setkey(lw_present_context *ctx, const uint8_t *key, uint16_t key_bitlen)
{
    if (key_bitlen != 80 && key_bitlen != 128) {
        return LW_ERR_PRESENT_INVALID_CONFIG;
    }
    ctx->key_bitlen = key_bitlen;
    memcpy(ctx->key, key, key_bitlen / 8);
    if (key_bitlen == 80) {
        // trashable key copies
        unsigned char key1[10];
        unsigned char key2[10];
        unsigned char i, j;
        memcpy(key1, key, 10);
        memcpy(ctx->round_key, key1, 8);
        for (i = 1; i < ROUNDS; i++) {
            // rotate left 61 bits
            for (j = 0; j < 10; j++) {
                key2[j] = (key1[(j + 7) % 10] << 5) |
                          (key1[(j + 8) % 10] >> 3);
            }
            memcpy(key1, key2, 10);

            // pass leftmost 4-bits through sBox
            key1[0] = (sBox[key1[0] >> 4] << 4) | (key1[0] & 0xF);

            // xor roundCounter into bits 15 through 19
            key1[8] ^= i << 7; // bit 15
            key1[7] ^= i >> 1; // bits 19-16
            memcpy(ctx->round_key[i], key1, 8);
        }
    } else {
        unsigned char key1[16];
        unsigned char key2[16];
        unsigned char i, j;
        memcpy(key1, key, 16);
        memcpy(ctx->round_key, key1, 8);
        for (i = 1; i < ROUNDS; i++) {
            // rotate left 61 bits
            for (j = 0; j < 16; j++) {
                key2[j] = (key1[(j + 7) % 16] << 5) | (key1[(j + 8) % 16] >> 3);
            }
            memcpy(key1, key2, 16);

            // pass leftmost 8-bits through sBoxes
            key1[0] = (sBox[key1[0] >> 4] << 4) | (sBox[key1[0] & 0xF]);

            // xor roundCounter into bits 62 through 66
            key1[8] ^= i << 6; // bits 63-62
            key1[7] ^= i >> 2; // bits 66-64

            memcpy(ctx->round_key[i], key1, 8);
        }
    }
    return 0;
}

int lw_present_crypt_ecb(lw_present_context *ctx, const uint8_t mode, const uint8_t *input, uint8_t *output)
{
    if (ctx->key_bitlen != 80 && ctx->key_bitlen != 128) {
        return LW_ERR_PRESENT_INVALID_CONFIG;
    }
    if (mode != PRESENT_ENCRYPT && mode != PRESENT_DECRYPT) {
        return LW_ERR_PRESENT_BAD_INPUT_DATA;
    }
    if (ctx->key_bitlen == 80 && mode == PRESENT_ENCRYPT) {
        unsigned char i, j;
        memcpy(output, input, 8);
        for (i = 0; i < ROUNDS - 1; i++) {
            for (int k = 0; k < 8; k++)
                output[k] ^= ctx->round_key[i][k];
            for (j = 0; j < 8; j++) {
                output[j] = (sBox[output[j] >> 4] << 4) | sBox[output[j] & 0xF];
            }
//            pLayer(output);
            {
                unsigned char m, n, indexVal, andVal;
                unsigned char initial[8];
                memcpy(initial, output, 8);
                for (m = 0; m < 8; m++) {
                    output[m] = 0;
                    for (n = 0; n < 8; n++) {
                        indexVal = 4 * (m % 2) + (3 - (n >> 1));
                        andVal = (8 >> (m >> 1)) << ((n % 2) << 2);
                        output[m] |= ((initial[indexVal] & andVal) != 0) << n;
                    }
                }
            }
        }
        for (int k = 0; k < 8; k++)
            output[k] ^= ctx->round_key[ROUNDS - 1][k];
    } else if (ctx->key_bitlen == 80 && mode == PRESENT_DECRYPT) {
        unsigned char i, j;
        memcpy(output, input, 8);
        for (i = ROUNDS - 1; i > 0; i--) {
            for (int k = 0; k < 8; k++)
                output[k] ^= ctx->round_key[i][k];
//            pLayerInverse(block);
            {
                unsigned char m, n, indexVal, andVal;
                unsigned char initial[PRESENT_BLOCK_SIZE_BYTES];
                memcpy(initial, output, PRESENT_BLOCK_SIZE_BYTES);
                for (m = 0; m < PRESENT_BLOCK_SIZE_BYTES; m++) {
                    output[m] = 0;
                    for (n = 0; n < 8; n++) {
                        indexVal = (7 - ((2 * n) % 8)) - (m < 4);
                        andVal = (7 - ((2 * m) % 8)) - (n < 4);
                        output[m] |= ((initial[indexVal] & (1 << andVal)) != 0) << n;
                    }
                }
            }
            for (j = 0; j < PRESENT_BLOCK_SIZE_BYTES; j++) {
                output[j] = (sBoxInverse[output[j] >> 4] << 4) | sBoxInverse[output[j] & 0xF];
            }
        }
        for (int k = 0; k < 8; k++)
            output[k] ^= ctx->round_key[0][k];
    } else if (ctx->key_bitlen == 128 && mode == PRESENT_ENCRYPT) {
        unsigned char i, j;
        memcpy(output, input, 8);
        for (i = 0; i < ROUNDS - 1; i++) {
            for (int k = 0; k < 8; k++)
                output[k] ^= ctx->round_key[i][k];
            for (j = 0; j < 8; j++) {
                output[j] = (sBox[output[j] >> 4] << 4) | sBox[output[j] & 0xF];
            }
            //pLayer(block)
            {
                unsigned char m, n, indexVal, andVal;
                unsigned char initial[8];
                memcpy(initial, output, 8);
                for (m = 0; m < 8; m++) {
                    output[m] = 0;
                    for (n = 0; n < 8; n++) {
                        indexVal = 4 * (m % 2) + (3 - (n >> 1));
                        andVal = (8 >> (m >> 1)) << ((n % 2) << 2);
                        output[m] |= ((initial[indexVal] & andVal) != 0) << n;
                    }
                }
            }
        }
        for (int k = 0; k < 8; k++)
            output[k] ^= ctx->round_key[ROUNDS - 1][k];
    } else if (ctx->key_bitlen == 128 && mode == PRESENT_DECRYPT) {
        unsigned char i, j;
        memcpy(output, input, 8);
        for (i = ROUNDS - 1; i > 0; i--) {
            for (int k = 0; k < 8; k++)
                output[k] ^= ctx->round_key[i][k];
            //pLayerInverse(block)
            {
                unsigned char m, n, indexVal, andVal;
                unsigned char initial[8];
                memcpy(initial, output, 8);
                for (m = 0; m < 8; m++) {
                    output[m] = 0;
                    for (n = 0; n < 8; n++) {
                        indexVal = (7 - ((2 * n) % 8)) - (m < 4);
                        andVal = (7 - ((2 * m) % 8)) - (n < 4);
                        output[m] |= ((initial[indexVal] & (1 << andVal)) != 0) << n;
                    }
                }
            }
            for (j = 0; j < 8; j++) {
                output[j] = (sBoxInverse[output[j] >> 4] << 4) | sBoxInverse[output[j] & 0xF];
            }
        }
        for (int k = 0; k < 8; k++)
            output[k] ^= ctx->round_key[0][k];
    }
    return 0;
}

int
lw_present_crypt_cbc(lw_present_context *ctx, const uint8_t mode, size_t length, uint8_t *iv, const uint8_t *input,
                     uint8_t *output)
{
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    if (ctx->key_bitlen != 80 && ctx->key_bitlen != 128) {
        return LW_ERR_PRESENT_INVALID_CONFIG;
    }
    if (mode != PRESENT_ENCRYPT && mode != PRESENT_DECRYPT) {
        return LW_ERR_PRESENT_BAD_INPUT_DATA;
    }
    if (length == 0) {
        return 0;
    }
    if (length % 8) {
        return LW_ERR_PRESENT_INVALID_INPUT_LENGTH;
    }
    const unsigned char *ivp = iv;
    unsigned char temp[8];
    if (mode == PRESENT_DECRYPT) {
        while (length > 0) {
            memcpy(temp, input, 8);
            ret = lw_present_crypt_ecb(ctx, mode, input, output);
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
            ret = lw_present_crypt_ecb(ctx, mode, output, output);
            if (ret != 0) {
                return ret;
            }
            ivp = output;
            input += 8;
            output += 8;
            length -= 8;
        }
    }
    memcpy(iv, ivp, 8);
    return 0;
}

int lw_present_crypt_ctr(lw_present_context *ctx, size_t length, uint8_t *nc_off, uint8_t nonce_counter[8],
                         uint8_t stream_block[8], const uint8_t *input, uint8_t *output)
{
    if (ctx->key_bitlen != 80 && ctx->key_bitlen != 128) {
        return LW_ERR_PRESENT_INVALID_CONFIG;
    }
    if (length == 0) {
        return 0;
    }
//    if (length % 8) {
//        return LW_ERR_PRESENT_INVALID_INPUT_LENGTH;
//    }
    int c, i;
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    n = *nc_off;
    if (n > 0b0111) {
        return LW_ERR_PRESENT_BAD_INPUT_DATA;
    }
    while (length--) {
        if (n == 0) {
            ret = lw_present_crypt_ecb(ctx, PRESENT_ENCRYPT, nonce_counter, stream_block);
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

int lw_present_self_test(int verbose)
{
    int ret;
    unsigned char key80[10] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23};
    unsigned char key128[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                0xCD, 0xEF};
    const unsigned char plaintext[32] =
            {0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2,
             0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4,
             0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D,
             0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE};
    unsigned char cipher_buffer[32] = {0};
    unsigned char dec_plain_buffer[32] = {0};
    unsigned char iv[8] = {0};
    unsigned char nonce_counter[8] = {0};

    lw_present_context ctx;
    lw_present_init(&ctx);
    lw_present_setkey(&ctx, key80, 80);
    lw_present_crypt_ecb(&ctx, PRESENT_ENCRYPT, plaintext, cipher_buffer);
    lw_present_crypt_ecb(&ctx, PRESENT_DECRYPT, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 8);
    if (ret != 0) {
        printf("Present 80 bit key ecb self test failed!\n");
        return ret;
    } else {
        printf("Present 80 bit key ecb self test passed!\n");
    }

    lw_present_init(&ctx);
    lw_present_setkey(&ctx, key128, 128);
    lw_present_crypt_ecb(&ctx, PRESENT_ENCRYPT, plaintext, cipher_buffer);
    lw_present_crypt_ecb(&ctx, PRESENT_DECRYPT, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 8);
    if (ret != 0) {
        printf("Present 128 bit key ecb self test failed!\n");
        return ret;
    } else {
        printf("Present 128 bit key ecb self test passed!\n");
    }

    lw_present_init(&ctx);
    lw_present_setkey(&ctx, key80, 80);
    lw_present_crypt_cbc(&ctx, PRESENT_ENCRYPT, 32, iv, plaintext, cipher_buffer);
    memset(iv, 0, 8);
    lw_present_crypt_cbc(&ctx, PRESENT_DECRYPT, 32, iv, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    if (ret != 0) {
        printf("Present 80 bit key cbc self test failed!\n");
        return ret;
    } else {
        printf("Present 80 bit key cbc self test passed!\n");
    }

    lw_present_init(&ctx);
    lw_present_setkey(&ctx, key128, 128);
    memset(iv, 0, 8);
    lw_present_crypt_cbc(&ctx, PRESENT_ENCRYPT, 32, iv, plaintext, cipher_buffer);
    memset(iv, 0, 8);
    lw_present_crypt_cbc(&ctx, PRESENT_DECRYPT, 32, iv, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    if (ret != 0) {
        printf("Present 128 bit key cbc self test failed!\n");
        return ret;
    } else {
        printf("Present 128 bit key cbc self test passed!\n");
    }

    uint8_t nc = 0;
    unsigned char stream_block[8] = {0};
    unsigned char nonce_counter_for_enc[8] = {0};
    memcpy(nonce_counter_for_enc, nonce_counter, 8);
    lw_present_init(&ctx);
    lw_present_setkey(&ctx, key80, 80);
    lw_present_crypt_ctr(&ctx, 32, &nc, nonce_counter_for_enc, stream_block, plaintext, cipher_buffer);
    nc = 0;
    lw_present_crypt_ctr(&ctx, 32, &nc, nonce_counter, stream_block, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    if (ret != 0) {
        printf("Present 80 bit key ctr self test failed!\n");
        return ret;
    } else {
        printf("Present 80 bit key ctr self test passed!\n");
    }

    memcpy(nonce_counter_for_enc, nonce_counter, 8);
    lw_present_init(&ctx);
    lw_present_setkey(&ctx, key128, 128);
    lw_present_crypt_ctr(&ctx, 32, &nc, nonce_counter_for_enc, stream_block, plaintext, cipher_buffer);
    nc = 0;
    lw_present_crypt_ctr(&ctx, 32, &nc, nonce_counter, stream_block, cipher_buffer, dec_plain_buffer);
    ret = memcmp(plaintext, dec_plain_buffer, 32);
    if (ret != 0) {
        printf("Present 128 bit key ctr self test failed!\n");
        return ret;
    } else {
        printf("Present 128 bit key ctr self test passed!\n");
    }
    return 0;
}
