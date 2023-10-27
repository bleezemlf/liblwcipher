#include "simon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

// Cipher Operation Macros
#define shift_one(x_word) (((x_word) << 1) | ((x_word) >> (word_size - 1)))
#define shift_eight(x_word) (((x_word) << 8) | ((x_word) >> (word_size - 8)))
#define shift_two(x_word) (((x_word) << 2) | ((x_word) >> (word_size - 2)))

#define rshift_three(x) (((x) >> 3) | (((x) & 0x7) << (word_size - 3)))
#define rshift_one(x)   (((x) >> 1) | (((x) & 0x1) << (word_size - 1)))

uint64_t z_arrays[5] = {0b0001100111000011010100100010111110110011100001101010010001011111,
                        0b0001011010000110010011111011100010101101000011001001111101110001,
                        0b0011001101101001111110001000010100011001001011000000111011110101,
                        0b0011110000101100111001010001001000000111101001100011010111011011,
                        0b0011110111001001010011000011101000000100011011010110011110001011};

// Valid Cipher Parameters
const uint8_t simon_rounds[] = {32, 36, 36, 42, 44, 52, 54, 68, 69, 72};
const uint8_t z_assign[] = {0, 0, 1, 2, 3, 2, 3, 2, 3, 4};

void lw_simon_init(lw_simon_context *ctx, uint8_t block_size)
{
    memset(ctx, 0, sizeof(lw_simon_context));
    ctx->block_size = block_size;
}

void lw_simon_free(lw_simon_context *ctx)
{
    memset(ctx, 0, sizeof(lw_simon_context));
}

int lw_simon_setkey(lw_simon_context *ctx, const uint8_t *key, uint16_t key_bitlen)
{
    ctx->key_bitlen = key_bitlen;
    switch (ctx->block_size) {
        case 4:
            if (ctx->key_bitlen != 64)
                return LW_ERR_SIMON_INVALID_CONFIG;
            ctx->round_limit = 32;
            ctx->encryptPtr = &Simon_Encrypt_32;
            ctx->decryptPtr = &Simon_Decrypt_32;
            break;
        case 6:
            if (ctx->key_bitlen != 72 && ctx->key_bitlen != 96)
                return LW_ERR_SIMON_INVALID_CONFIG;
            ctx->round_limit = 36;
            ctx->encryptPtr = Simon_Encrypt_48;
            ctx->decryptPtr = Simon_Decrypt_48;
            break;
        case 8:
            if (key_bitlen == 96)
                ctx->round_limit = 42;
            else if (key_bitlen == 128)
                ctx->round_limit = 44;
            else
                return LW_ERR_SIMON_INVALID_CONFIG;
            ctx->encryptPtr = Simon_Encrypt_64;
            ctx->decryptPtr = Simon_Decrypt_64;
            break;
        case 12:
            if (ctx->key_bitlen == 96)
                ctx->round_limit = 52;
            else if (ctx->key_bitlen == 144)
                ctx->round_limit = 54;
            else
                return LW_ERR_SIMON_INVALID_CONFIG;
            ctx->encryptPtr = Simon_Encrypt_96;
            ctx->decryptPtr = Simon_Decrypt_96;
            break;
        case 16:
            if (ctx->key_bitlen == 128)
                ctx->round_limit = 68;
            else if (ctx->key_bitlen == 192)
                ctx->round_limit = 69;
            else if (ctx->key_bitlen == 256)
                ctx->round_limit = 72;
            else
                return LW_ERR_SIMON_INVALID_CONFIG;
            ctx->encryptPtr = Simon_Encrypt_128;
            ctx->decryptPtr = Simon_Decrypt_128;
            break;
        default:
            return LW_ERR_SIMON_INVALID_CONFIG;
    }
    uint8_t word_size = ctx->block_size << 2;
    uint8_t word_bytes = word_size >> 3;
    uint16_t key_words = ctx->key_bitlen / word_size;
    uint64_t sub_keys[4] = {};
    uint64_t mod_mask = ULLONG_MAX >> (64 - word_size);
    // Setup
    for (int i = 0; i < key_words; i++) {
        memcpy(&sub_keys[i], key + (word_bytes * i), word_bytes);
    }
    uint64_t tmp1, tmp2;
    uint64_t c = 0xFFFFFFFFFFFFFFFC;
    // Store First Key Schedule Entry
    memcpy(ctx->key_schedule, &sub_keys[0], word_bytes);
    for (int i = 0; i < ctx->round_limit - 1; i++) {
        tmp1 = rshift_three(sub_keys[key_words - 1]);

        if (key_words == 4) {
            tmp1 ^= sub_keys[1];
        }

        tmp2 = rshift_one(tmp1);
        tmp1 ^= sub_keys[0];
        tmp1 ^= tmp2;

        tmp2 = c ^ ((z_arrays[ctx->z_seq] >> (i % 62)) & 1);

        tmp1 ^= tmp2;

        // Shift Sub Words
        for (int j = 0; j < (key_words - 1); j++) {
            sub_keys[j] = sub_keys[j + 1];
        }
        sub_keys[key_words - 1] = tmp1 & mod_mask;

        // Append sub key to key schedule
        memcpy(ctx->key_schedule + (word_bytes * (i + 1)), &sub_keys[0], word_bytes);

    }
    return 0;
}

int lw_simon_crypt_ecb(lw_simon_context *ctx, int mode, const uint8_t input[8], uint8_t output[8])
{
    if (mode != SIMON_ENCRYPT && mode != SIMON_DECRYPT) {
        return LW_ERR_SIMON_BAD_INPUT_DATA;
    } else if (ctx->round_limit == 0) {
        return LW_ERR_SIMON_INVALID_CONFIG;
    } else if (mode == SIMON_ENCRYPT)
        (*ctx->encryptPtr)(ctx->round_limit, ctx->key_schedule, input, output);
    else if (mode == SIMON_DECRYPT)
        (*ctx->decryptPtr)(ctx->round_limit, ctx->key_schedule, input, output);
    return 0;
}

int
lw_simon_crypt_cbc(lw_simon_context *ctx, int mode, size_t length, uint8_t *iv, const uint8_t *input, uint8_t *output)
{
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *temp = (uint8_t *) malloc(ctx->block_size);
    if (mode != SIMON_ENCRYPT && mode != SIMON_DECRYPT) {
        return LW_ERR_SIMON_BAD_INPUT_DATA;
    }
    /* Nothing to do if length is zero. */
    if (length == 0) {
        return 0;
    }
    if (length % ctx->block_size) {
        return LW_ERR_SIMON_INVALID_INPUT_LENGTH;
    }
    const unsigned char *ivp = iv;
    if (mode == SIMON_DECRYPT) {
        while (length > 0) {
            memcpy(temp, input, ctx->block_size);
            ret = lw_simon_crypt_ecb(ctx, mode, input, output);
            if (ret != 0) {
                return ret;
            }
            for (int i = 0; i < ctx->block_size; i++) {
                output[i] = iv[i] ^ output[i];
            }
            memcpy(iv, temp, ctx->block_size);
            input += ctx->block_size;
            output += ctx->block_size;
            length -= ctx->block_size;
        }
    } else {
        while (length > 0) {
            for (int i = 0; i < ctx->block_size; i++) {
                output[i] = ivp[i] ^ input[i];
            }
            ret = lw_simon_crypt_ecb(ctx, mode, output, output);
            if (ret != 0) {
                return ret;
            }
            ivp = output;
            input += ctx->block_size;
            output += ctx->block_size;
            length -= ctx->block_size;
        }
        memcpy(iv, ivp, ctx->block_size);
    }
    free(temp);
    ret = 0;
    return ret;
}

int
lw_simon_crypt_ctr(lw_simon_context *ctx, size_t length, uint8_t *nc_off, uint8_t nonce_counter[8],
                   uint8_t stream_block[8],
                   const uint8_t *input, uint8_t *output)
{
    int c, i;
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    n = *nc_off;
    if (n > ctx->block_size) {
        return LW_ERR_SIMON_BAD_INPUT_DATA;
    }
    while (length--) {
        if (n == 0) {
            ret = lw_simon_crypt_ecb(ctx, SIMON_ENCRYPT, nonce_counter, stream_block);
            if (ret != 0) {
                return ret;
            }
            for (i = ctx->block_size; i > 0; i--) {
                if (++nonce_counter[i - 1] != 0) {
                    break;
                }
            }
        }
        c = *input++;
        *output++ = (unsigned char) (c ^ stream_block[n]);
        n = (n + 1) % ctx->block_size;
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

int lw_simon_self_test(int verbose)
{
    lw_simon_context ctx;
    uint8_t my_IV[] = {0x32, 0x14, 0x76, 0x58};
    uint8_t my_counter[] = {0x2F, 0x3D, 0x5C, 0x7B};
    uint8_t ciphertext_buffer[16];
    uint8_t plaintext_buffer[16];
    int ret;
    // Simon 64/32 Test
    // Key: 1918 1110 0908 0100 Plaintext: 6565 6877 Ciphertext: c69b e9bb
    {
        printf("**** Test Simon 64/32 ****\n");
        {
            //ecb mode test
            uint8_t simon64_32_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
            uint8_t simon64_32_plain[] = {0x77, 0x68, 0x65, 0x65};
            lw_simon_init(&ctx, 4);
            ret = lw_simon_setkey(&ctx, simon64_32_key, 64);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon64_32_plain, ciphertext_buffer);
            lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon64_32_plain, sizeof(simon64_32_plain));
            if (ret != 0) {
                printf("ECB Test Failed!\n");
                return ret;
            } else {
                printf("ECB Test Passed!\n");
            }
        }
        {
            //cbc mode test
            uint8_t simon64_32_plain[] = {0x77, 0x68, 0x65, 0x65, 0x77, 0x68, 0x65, 0x65};
            uint8_t simon64_32_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
            lw_simon_init(&ctx, 4);
            ret = lw_simon_setkey(&ctx, simon64_32_key, 64);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[4] = {};
            lw_simon_crypt_cbc(&ctx, SIMON_ENCRYPT, 8, iv, simon64_32_plain, ciphertext_buffer);
            memset(iv, 0, 4);
            lw_simon_crypt_cbc(&ctx, SIMON_DECRYPT, 8, iv, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon64_32_plain, sizeof(simon64_32_plain));
            if (ret != 0) {
                printf("CBC Test Failed!\n");
                return ret;
            } else {
                printf("CBC Test Passed!\n");
            }
        }
        {
            //CTR mode test
            uint8_t simon64_32_plain[] = {0x77, 0x68, 0x65, 0x65, 0x77, 0x68, 0x65, 0x65};
            uint8_t simon64_32_key[] = {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19};
            lw_simon_init(&ctx, 4);
            ret = lw_simon_setkey(&ctx, simon64_32_key, 64);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[4] = {};
            uint8_t nc_off = 0;
            lw_simon_crypt_ctr(&ctx, 8, &nc_off, iv, my_counter, simon64_32_plain, ciphertext_buffer);
            memset(iv, 0, 4);
            lw_simon_crypt_ctr(&ctx, 8, &nc_off, iv, my_counter, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon64_32_plain, sizeof(simon64_32_plain));
            if (ret != 0) {
                printf("CTR Test Failed!\n");
                return ret;
            } else {
                printf("CTR Test Passed!\n");
            }
        }
    }

    // Simon 72/48 Test
    // Key: 121110 0a0908 020100 Plaintext: 612067 6e696c Ciphertext: dae5ac 292cac
    {
        printf("**** Test Simon 72/48 ****\n");
        {
            uint8_t simon72_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12};
            uint8_t simon72_48_plain[] = {0x6c, 0x69, 0x6E, 0x67, 0x20, 0x61};
            lw_simon_init(&ctx, 6);
            ret = lw_simon_setkey(&ctx, simon72_48_key, 72);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon72_48_plain, ciphertext_buffer);
            lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon72_48_plain, sizeof(simon72_48_plain));
            if (ret != 0) {
                printf("ECB Test Failed!\n");
                return ret;
            } else {
                printf("ECB Test Passed!\n");
            }
        }
        {
            // CBC mode test
            uint8_t simon72_48_plain[] = {0x6c, 0x69, 0x6E, 0x67, 0x20, 0x61, 0x6c, 0x69, 0x6E, 0x67, 0x20, 0x61};
            uint8_t simon72_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12};
            lw_simon_init(&ctx, 6);
            ret = lw_simon_setkey(&ctx, simon72_48_key, 72);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[6] = {0};
            lw_simon_crypt_cbc(&ctx, SIMON_ENCRYPT, 12, iv, simon72_48_plain, ciphertext_buffer);
            memset(iv, 0, 6);
            lw_simon_crypt_cbc(&ctx, SIMON_DECRYPT, 12, iv, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon72_48_plain, sizeof(simon72_48_plain));
            if (ret != 0) {
                printf("CBC Test Failed!\n");
                return ret;
            } else {
                printf("CBC Test Passed!\n");
            }
        }
    }

    // Simon 96/48 Test
    // Key: 1a1918 121110 0a0908 020100 Plaintext: 726963 20646e Ciphertext: 6e06a5 acf156
    {
        printf("**** Test Simon 96/48 ****\n");
        {
            uint8_t simon96_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a};
            uint8_t simon96_48_plain[] = {0x6e, 0x64, 0x20, 0x63, 0x69, 0x72};
            lw_simon_init(&ctx, 6);
            ret = lw_simon_setkey(&ctx, simon96_48_key, 96);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon96_48_plain, ciphertext_buffer);
            lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon96_48_plain, sizeof(simon96_48_plain));
            if (ret != 0) {
                printf("ECB Test Failed!\n");
                return ret;
            } else {
                printf("ECB Test Passed!\n");
            }
        }
        {
            // cbc mode test
            uint8_t simon96_48_plain[] = {0x6e, 0x64, 0x20, 0x63, 0x69, 0x72, 0x6e, 0x64, 0x20, 0x63, 0x69, 0x72};
            uint8_t simon96_48_key[] = {0x00, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a};
            lw_simon_init(&ctx, 6);
            ret = lw_simon_setkey(&ctx, simon96_48_key, 96);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[6] = {0};
            lw_simon_crypt_cbc(&ctx, SIMON_ENCRYPT, 12, iv, simon96_48_plain, ciphertext_buffer);
            memset(iv, 0, 6);
            lw_simon_crypt_cbc(&ctx, SIMON_DECRYPT, 12, iv, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon96_48_plain, sizeof(simon96_48_plain));
            if (ret != 0) {
                printf("CBC Test Failed!\n");
                return ret;
            } else {
                printf("CBC Test Passed!\n");
            }
        }
    }


    // Simon 96/64 Test
    // Key: 13121110 0b0a0908 03020100 Plaintext: 6f722067 6e696c63 Ciphertext: 5ca2e27f 111a8fc8
    {
        printf("**** Test Simon 96/64 ****\n");
        {
            uint8_t simon96_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13};
            uint8_t simon96_64_plain[] = {0x63, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x72, 0x6f};
            lw_simon_init(&ctx, 8);
            ret = lw_simon_setkey(&ctx, simon96_64_key, 96);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon96_64_plain, ciphertext_buffer);
            lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon96_64_plain, sizeof(simon96_64_plain));
            if (ret != 0) {
                printf("ECB Test Failed!\n");
                return ret;
            } else {
                printf("ECB Test Passed!\n");
            }
        }
        {
            // cbc mode test
            uint8_t simon96_64_plain[] = {0x63, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x72, 0x6f, 0x63, 0x6c, 0x69, 0x6e, 0x67,
                                          0x20, 0x72, 0x6f};
            uint8_t simon96_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13};
            lw_simon_init(&ctx, 8);
            ret = lw_simon_setkey(&ctx, simon96_64_key, 96);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[8] = {0};
            lw_simon_crypt_cbc(&ctx, SIMON_ENCRYPT, 16, iv, simon96_64_plain, ciphertext_buffer);
            memset(iv, 0, 8);
            lw_simon_crypt_cbc(&ctx, SIMON_DECRYPT, 16, iv, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon96_64_plain, sizeof(simon96_64_plain));
            if (ret != 0) {
                printf("CBC Test Failed!\n");
                return ret;
            } else {
                printf("CBC Test Passed!\n");
            }
        }
    }


    // Simon 128/64 Test
    // Key: 1b1a1918 13121110 0b0a0908 03020100 Plaintext: 656b696c 20646e75 Ciphertext: 44c8fc20 b9dfa07a
    {
        printf("**** Test Simon 128/64 ****\n");
        {
            uint8_t simon128_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18,
                                         0x19,
                                         0x1A, 0x1B};
            uint8_t simon128_64_plain[] = {0x75, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65};
            lw_simon_init(&ctx, 8);
            ret = lw_simon_setkey(&ctx, simon128_64_key, 128);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon128_64_plain, ciphertext_buffer);
            lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon128_64_plain, sizeof(simon128_64_plain));
            if (ret != 0) {
                printf("ECB Test Failed!\n");
                return ret;
            } else {
                printf("ECB Test Passed!\n");
            }
        }
        {
            // CBC mode test
            uint8_t simon128_64_plain[] = {0x75, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65, 0x75, 0x6e, 0x64, 0x20, 0x6c,
                                           0x69, 0x6b, 0x65};
            uint8_t simon128_64_key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x11, 0x12, 0x13, 0x18,
                                         0x19, 0x1A, 0x1B};
            lw_simon_init(&ctx, 8);
            ret = lw_simon_setkey(&ctx, simon128_64_key, 128);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[8] = {0};
            lw_simon_crypt_cbc(&ctx, SIMON_ENCRYPT, 16, iv, simon128_64_plain, ciphertext_buffer);
            memset(iv, 0, 8);
            lw_simon_crypt_cbc(&ctx, SIMON_DECRYPT, 16, iv, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon128_64_plain, sizeof(simon128_64_plain));
            if (ret != 0) {
                printf("CBC Test Failed!\n");
                return ret;
            } else {
                printf("CBC Test Passed!\n");
            }
        }
    }


    // Simon 96/96 Test
    // Key: 0d0c0b0a0908 050403020100 Plaintext: 2072616c6c69 702065687420 Ciphertext: 602807a462b4 69063d8ff082
    {
        printf("**** Test Simon 96/96 ****\n");
        {
            uint8_t simon96_96_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D};
            uint8_t simon96_96_plain[] = {0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x69, 0x6c, 0x6c, 0x61, 0x72, 0x20};
            lw_simon_init(&ctx, 12);
            ret = lw_simon_setkey(&ctx, simon96_96_key, 96);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon96_96_plain, ciphertext_buffer);
            lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon96_96_plain, sizeof(simon96_96_plain));
            if (ret != 0) {
                printf("ECB Test Failed!\n");
                return ret;
            } else {
                printf("ECB Test Passed!\n");
            }
        }
        {
            //CBC mode test
            uint8_t simon96_96_plain[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D};
            uint8_t simon96_96_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D};
            lw_simon_init(&ctx, 12);
            ret = lw_simon_setkey(&ctx, simon96_96_key, 96);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[12] = {0};
            lw_simon_crypt_cbc(&ctx, SIMON_ENCRYPT, 24, iv, simon96_96_plain, ciphertext_buffer);
            memset(iv, 0, 12);
            lw_simon_crypt_cbc(&ctx, SIMON_DECRYPT, 24, iv, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon96_96_plain, sizeof(simon96_96_plain));
            if (ret != 0) {
                printf("CBC Test Failed!\n");
                return ret;
            } else {
                printf("CBC Test Passed!\n");
            }
        }
    }


    // Simon 144/96 Test
    // Key: 151413121110 0d0c0b0a0908 050403020100 Plaintext: 746168742074 73756420666f Ciphertext: ecad1c6c451e 3f59c5db1ae9
    {
        printf("**** Test Simon 144/96 ****\n");
        {
            uint8_t simon144_96_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x10,
                                         0x11,
                                         0x12, 0x13, 0x14, 0x15};
            uint8_t simon144_96_plain[] = {0x6f, 0x66, 0x20, 0x64, 0x75, 0x73, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74};
            lw_simon_init(&ctx, 12);
            ret = lw_simon_setkey(&ctx, simon144_96_key, 144);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon144_96_plain, ciphertext_buffer);
            lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon144_96_plain, sizeof(simon144_96_plain));
            if (ret != 0) {
                printf("ECB Test Failed!\n");
                return ret;
            } else {
                printf("ECB Test Passed!\n");
            }
        }
        {
            //CBC mode test
            uint8_t simon144_96_plain[] = {0x6f, 0x66, 0x20, 0x64, 0x75, 0x73, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74,
                                           0x6f, 0x66, 0x20, 0x64, 0x75, 0x73, 0x74, 0x20, 0x74, 0x68, 0x61, 0x74};
            uint8_t simon144_96_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
            lw_simon_init(&ctx, 12);
            ret = lw_simon_setkey(&ctx, simon144_96_key, 144);
            if (ret != 0) {
                printf("lw_simon_setkey error: %d\n", ret);
                return ret;
            }
            uint8_t iv[12] = {0};
            lw_simon_crypt_cbc(&ctx, SIMON_ENCRYPT, 24, iv, simon144_96_plain, ciphertext_buffer);
            memset(iv, 0, 12);
            lw_simon_crypt_cbc(&ctx, SIMON_DECRYPT, 24, iv, ciphertext_buffer, plaintext_buffer);
            ret = memcmp(plaintext_buffer, simon144_96_plain, sizeof(simon144_96_plain));
            if (ret != 0) {
                printf("CBC Test Failed!\n");
                return ret;
            } else {
                printf("CBC Test Passed!\n");
            }
        }
    }


    // Simon 128/128 Test
    // Key: 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 6373656420737265 6c6c657661727420 Ciphertext: 49681b1e1e54fe3f 65aa832af84e0bbc
    {
        printf("**** Test Simon 128/128 ****\n");
        uint8_t simon128_128_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                      0x0D, 0x0E, 0x0F};
        uint8_t simon128_128_plain[] = {0x20, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x20, 0x64,
                                        0x65, 0x73, 0x63};
        lw_simon_init(&ctx, 16);
        ret = lw_simon_setkey(&ctx, simon128_128_key, 128);
        if (ret != 0) {
            printf("lw_simon_setkey error: %d\n", ret);
            return ret;
        }
        lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon128_128_plain, ciphertext_buffer);
        lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
        ret = memcmp(plaintext_buffer, simon128_128_plain, sizeof(simon128_128_plain));
        if (ret != 0) {
            printf("Test Failed!\n");
            return ret;
        } else {
            printf("Test Passed!\n");
        }
    }


    // Simon 192/128 Test
    // Key: 1716151413121110 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 206572656874206e 6568772065626972 Ciphertext: c4ac61effcdc0d4f 6c9c8d6e2597b85b
    {
        printf("**** Test Simon 192/128 ****\n");
        uint8_t simon192_128_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                      0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
        uint8_t simon192_128_plain[] = {0x72, 0x69, 0x62, 0x65, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65,
                                        0x72, 0x65, 0x20};
        lw_simon_init(&ctx, 16);
        ret = lw_simon_setkey(&ctx, simon192_128_key, 192);
        if (ret != 0) {
            printf("lw_simon_setkey error: %d\n", ret);
            return ret;
        }
        lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon192_128_plain, ciphertext_buffer);
        lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
        ret = memcmp(plaintext_buffer, simon192_128_plain, sizeof(simon192_128_plain));
        if (ret != 0) {
            printf("Test Failed!\n");
            return ret;
        } else {
            printf("Test Passed!\n");
        }
    }


    // Simon 256/128 Test
    // Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100 Plaintext: 74206e69206d6f6f 6d69732061207369 Ciphertext: 8d2b5579afc8a3a0 3bf72a87efe7b868
    {
        printf("**** Test Simon 256/128 ****\n");
        uint8_t simon256_128_key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                      0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                                      0x1A, 0x1B, 0x1C, 0x1d, 0x1e, 0x1f};
        uint8_t simon256_128_plain[] = {0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6d, 0x6f, 0x6f, 0x6d, 0x20, 0x69,
                                        0x6e, 0x20, 0x74};
        lw_simon_init(&ctx, 16);
        ret = lw_simon_setkey(&ctx, simon256_128_key, 256);
        if (ret != 0) {
            printf("lw_simon_setkey error: %d\n", ret);
            return ret;
        }
        lw_simon_crypt_ecb(&ctx, SIMON_ENCRYPT, simon256_128_plain, ciphertext_buffer);
        lw_simon_crypt_ecb(&ctx, SIMON_DECRYPT, ciphertext_buffer, plaintext_buffer);
        ret = memcmp(plaintext_buffer, simon256_128_plain, sizeof(simon256_128_plain));
        if (ret != 0) {
            printf("Test Failed!\n");
            return ret;
        } else {
            printf("Test Passed!\n");
        }
    }
    return 0;
}


void
Simon_Encrypt_32(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext, uint8_t *ciphertext)
{

    const uint8_t word_size = 16;
    uint16_t *y_word = (uint16_t *) ciphertext;
    uint16_t *x_word = (((uint16_t *) ciphertext) + 1);

    *y_word = *(uint16_t *) plaintext;
    *x_word = *(((uint16_t *) plaintext) + 1);

    uint16_t *round_key_ptr = (uint16_t *) key_schedule;

    for (uint8_t i = 0; i < round_limit; i++) {

        // Shift, AND , XOR ops
        uint16_t temp = (shift_one(*x_word) & shift_eight(*x_word)) ^ *y_word ^ shift_two(*x_word);

        // Feistel Cross
        *y_word = *x_word;

        // XOR with Round Key
        *x_word = temp ^ *(round_key_ptr + i);
    }
}

void Simon_Encrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext)
{

    const uint8_t word_size = 24;

    bword_24 intrd = *(bword_24 *) plaintext;
    uint32_t y_word = intrd.data;
    intrd = *((bword_24 *) (plaintext + 3));
    uint32_t x_word = intrd.data;

    for (uint8_t i = 0; i < round_limit; i++) {

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one(x_word) & shift_eight(x_word)) ^ y_word ^ shift_two(x_word);

        // Feistel Cross
        y_word = x_word;

        // XOR with Round Key
        x_word = (temp ^ (*((bword_24 *) (key_schedule + (i * 3)))).data) & 0xFFFFFF;
    }
    // Assemble Ciphertext Output Array
    intrd.data = y_word;
    bword_24 *intrd_ptr = (bword_24 *) ciphertext;
    *intrd_ptr = intrd;

    intrd.data = x_word;
    intrd_ptr = (bword_24 *) (ciphertext + 3);
    *intrd_ptr = intrd;
}

void Simon_Encrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext)
{

    const uint8_t word_size = 32;
    uint32_t *y_word = (uint32_t *) ciphertext;
    uint32_t *x_word = (((uint32_t *) ciphertext) + 1);
    *y_word = *(uint32_t *) plaintext;
    *x_word = *(((uint32_t *) plaintext) + 1);
    uint32_t *round_key_ptr = (uint32_t *) key_schedule;

    for (uint8_t i = 0; i < round_limit; i++) {

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one(*x_word) & shift_eight(*x_word)) ^ *y_word ^ shift_two(*x_word);

        // Feistel Cross
        *y_word = *x_word;

        // XOR with Round Key
        *x_word = temp ^ *(round_key_ptr + i);
    }
}

void Simon_Encrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext)
{

    const uint8_t word_size = 48;

    bword_48 intrd = *(bword_48 *) plaintext;
    uint64_t y_word = intrd.data;
    intrd = *((bword_48 *) (plaintext + 6));
    uint64_t x_word = intrd.data;

    for (uint8_t i = 0; i < round_limit; i++) {

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one(x_word) & shift_eight(x_word)) ^ y_word ^ shift_two(x_word);

        // Feistel Cross
        y_word = x_word;

        // XOR with Round Key
        x_word = (temp ^ (*((bword_48 *) (key_schedule + (i * 6)))).data) & 0xFFFFFFFFFFFF;
    }
    // Assemble Ciphertext Output Array
    intrd.data = y_word;
    bword_48 *intrd_ptr = (bword_48 *) ciphertext;
    *intrd_ptr = intrd;

    intrd.data = x_word;
    intrd_ptr = (bword_48 *) (ciphertext + 6);
    *intrd_ptr = intrd;

}

void Simon_Encrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                       uint8_t *ciphertext)
{

    const uint8_t word_size = 64;
    uint64_t *y_word = (uint64_t *) ciphertext;
    uint64_t *x_word = (((uint64_t *) ciphertext) + 1);
    *y_word = *(uint64_t *) plaintext;
    *x_word = *(((uint64_t *) plaintext) + 1);
    uint64_t *round_key_ptr = (uint64_t *) key_schedule;


    for (uint8_t i = 0; i < round_limit; i++) {

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one(*x_word) & shift_eight(*x_word)) ^ *y_word ^ shift_two(*x_word);

        // Feistel Cross
        *y_word = *x_word;

        // XOR with Round Key
        *x_word = temp ^ *(round_key_ptr + i);
    }
}

void Simon_Decrypt_32(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext)
{

    const uint8_t word_size = 16;
    uint16_t *x_word = (uint16_t *) plaintext;
    uint16_t *y_word = ((uint16_t *) plaintext) + 1;
    uint16_t *round_key_ptr = (uint16_t *) key_schedule;

    *x_word = *(uint16_t *) ciphertext;
    *y_word = *(((uint16_t *) ciphertext) + 1);

    for (int8_t i = round_limit - 1; i >= 0; i--) {

        // Shift, AND , XOR ops
        uint16_t temp = (shift_one(*x_word) & shift_eight(*x_word)) ^ *y_word ^ shift_two(*x_word);

        // Feistel Cross
        *y_word = *x_word;

        // XOR with Round Key
        *x_word = temp ^ *(round_key_ptr + i);
    }
}

void Simon_Decrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext)
{
    const uint8_t word_size = 24;

    bword_24 intrd = *(bword_24 *) ciphertext;
    uint32_t x_word = intrd.data;
    intrd = *((bword_24 *) (ciphertext + 3));
    uint32_t y_word = intrd.data;

    for (int8_t i = round_limit - 1; i >= 0; i--) {

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one(x_word) & shift_eight(x_word)) ^ y_word ^ shift_two(x_word);

        // Feistel Cross
        y_word = x_word;

        // XOR with Round Key
        x_word = (temp ^ (*((bword_24 *) (key_schedule + (i * 3)))).data) & 0xFFFFFF;
    }
    // Assemble plaintext Output Array
    intrd.data = x_word;
    bword_24 *intrd_ptr = (bword_24 *) plaintext;
    *intrd_ptr = intrd;

    intrd.data = y_word;
    intrd_ptr = (bword_24 *) (plaintext + 3);
    *intrd_ptr = intrd;
}

void Simon_Decrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext)
{

    const uint8_t word_size = 32;
    uint32_t *x_word = (uint32_t *) plaintext;
    uint32_t *y_word = ((uint32_t *) plaintext) + 1;
    uint32_t *round_key_ptr = (uint32_t *) key_schedule;

    *x_word = *(uint32_t *) ciphertext;
    *y_word = *(((uint32_t *) ciphertext) + 1);

    for (int8_t i = round_limit - 1; i >= 0; i--) {

        // Shift, AND , XOR ops
        uint32_t temp = (shift_one(*x_word) & shift_eight(*x_word)) ^ *y_word ^ shift_two(*x_word);

        // Feistel Cross
        *y_word = *x_word;

        // XOR with Round Key
        *x_word = temp ^ *(round_key_ptr + i);
    }
}

void Simon_Decrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext)
{
    const uint8_t word_size = 48;
    bword_48 intrd = *(bword_48 *) ciphertext;
    uint64_t x_word = intrd.data;
    intrd = *((bword_48 *) (ciphertext + 6));
    uint64_t y_word = intrd.data;

    for (int8_t i = round_limit - 1; i >= 0; i--) {

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one(x_word) & shift_eight(x_word)) ^ y_word ^ shift_two(x_word);

        // Feistel Cross
        y_word = x_word;

        // XOR with Round Key
        x_word = (temp ^ (*((bword_48 *) (key_schedule + (i * 6)))).data) & 0xFFFFFFFFFFFF;
    }
    // Assemble Plaintext Output Array
    intrd.data = x_word;
    bword_48 *intrd_ptr = (bword_48 *) plaintext;
    *intrd_ptr = intrd;

    intrd.data = y_word;
    intrd_ptr = (bword_48 *) (plaintext + 6);
    *intrd_ptr = intrd;
}

void Simon_Decrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                       uint8_t *plaintext)
{

    const uint8_t word_size = 64;
    uint64_t *x_word = (uint64_t *) plaintext;
    uint64_t *y_word = ((uint64_t *) plaintext) + 1;
    uint64_t *round_key_ptr = (uint64_t *) key_schedule;

    *x_word = *(uint64_t *) ciphertext;
    *y_word = *(((uint64_t *) ciphertext) + 1);

    for (int8_t i = round_limit - 1; i >= 0; i--) {

        // Shift, AND , XOR ops
        uint64_t temp = (shift_one(*x_word) & shift_eight(*x_word)) ^ *y_word ^ shift_two(*x_word);

        // Feistel Cross
        *y_word = *x_word;

        // XOR with Round Key
        *x_word = temp ^ *(round_key_ptr + i);
    }
}