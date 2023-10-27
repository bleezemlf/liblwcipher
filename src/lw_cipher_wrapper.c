#include "lw_cipher_wrapper.h"
#include "lwcipher.h"
#include <stdlib.h>

enum lw_cipher_base_index
{
    LW_CIPHER_BASE_INDEX_XTEA,
    LW_CIPHER_BASE_INDEX_XXTEA,
    LW_CIPHER_BASE_INDEX_SIMON,
    LW_CIPHER_BASE_INDEX_SPECK,
    LW_CIPHER_BASE_INDEX_PRESENT
};

static int xtea_crypt_ecb_wrap(void *ctx, lw_operation_t operation,
                               const uint8_t *input, uint8_t *output)
{
    return lw_xtea_crypt_ecb((lw_xtea_context *) ctx, operation, input, output);
}

static int xtea_crypt_cbc_wrap(void *ctx, lw_operation_t operation,
                               size_t length, uint8_t *iv,
                               const uint8_t *input, uint8_t *output)
{
    return lw_xtea_crypt_cbc((lw_xtea_context *) ctx, operation, length, iv,
                             input, output);
}

static int xtea_crypt_ctr_wrap(void *ctx, size_t length, uint8_t *nc_off,
                               uint8_t *nonce_counter,
                               uint8_t *stream_block, const uint8_t *input,
                               uint8_t *output)
{
    return lw_xtea_crypt_ctr((lw_xtea_context *) ctx, length, nc_off,
                             nonce_counter, stream_block, input, output);
}

static int xtea_setkey_enc_wrap(void *ctx, const uint8_t *key,
                                unsigned int key_bitlen)
{
    return lw_xtea_setkey((lw_xtea_context *) ctx, key, key_bitlen);
}

static int xtea_setkey_dec_wrap(void *ctx, const uint8_t *key,
                                unsigned int key_bitlen)
{
    return lw_xtea_setkey((lw_xtea_context *) ctx, key, key_bitlen);
}

static void *xtea_ctx_alloc(uint8_t)
{
    lw_xtea_context *ctx = (lw_xtea_context *) malloc(sizeof(lw_xtea_context));
    if (ctx == NULL) {
        return NULL;
    }
    lw_xtea_init(ctx);
    return ctx;
}

static void xtea_ctx_free(void *ctx)
{
    lw_xtea_free((lw_xtea_context *) ctx);
    free(ctx);
}

static const lw_cipher_base_t xtea_info = {
        LW_CIPHER_ID_XTEA,
        xtea_crypt_ecb_wrap,
        xtea_crypt_cbc_wrap,
        xtea_crypt_ctr_wrap,
        xtea_setkey_enc_wrap,
        xtea_setkey_dec_wrap,
        xtea_ctx_alloc,
        xtea_ctx_free
};

static const lw_cipher_info_t lw_cipher_xtea_ecb_info = {
        "XTEA-ECB",
        8,
        0,
        128,
        LW_MODE_ECB,
        LW_CIPHER_XTEA_ECB,
        0,
        LW_CIPHER_BASE_INDEX_XTEA
};

static const lw_cipher_info_t lw_cipher_xtea_cbc_info = {
        "XTEA-CBC",
        8,
        8,
        128,
        LW_MODE_CBC,
        LW_CIPHER_XTEA_CBC,
        0,
        LW_CIPHER_BASE_INDEX_XTEA
};

static const lw_cipher_info_t lw_cipher_xtea_ctr_info = {
        "XTEA-CTR",
        8,
        8,
        128,
        LW_MODE_CTR,
        LW_CIPHER_XTEA_CTR,
        0,
        LW_CIPHER_BASE_INDEX_XTEA
};

static int xxtea_crypt_ecb_wrap(void *ctx, lw_operation_t operation,
                                const uint8_t *input, uint8_t *output)
{
    return lw_xxtea_crypt_ecb((lw_xxtea_context *) ctx, operation, input,
                              output);
}

static int xxtea_crypt_cbc_wrap(void *ctx, lw_operation_t operation,
                                size_t length, uint8_t *iv,
                                const uint8_t *input, uint8_t *output)
{
    return lw_xxtea_crypt_cbc((lw_xxtea_context *) ctx, operation, length, iv,
                              input, output);
}

static int xxtea_crypt_ctr_wrap(void *ctx, size_t length, uint8_t *nc_off,
                                uint8_t *nonce_counter,
                                uint8_t *stream_block, const uint8_t *input,
                                uint8_t *output)
{
    return lw_xxtea_crypt_ctr((lw_xxtea_context *) ctx, length, nc_off,
                              nonce_counter, stream_block, input, output);
}

static int xxtea_setkey_enc_wrap(void *ctx, const uint8_t *key,
                                 unsigned int key_bitlen)
{
    return lw_xxtea_setkey((lw_xxtea_context *) ctx, key, key_bitlen);
}

static int xxtea_setkey_dec_wrap(void *ctx, const uint8_t *key,
                                 unsigned int key_bitlen)
{
    return lw_xxtea_setkey((lw_xxtea_context *) ctx, key, key_bitlen);
}

static void *xxtea_ctx_alloc(uint8_t)
{
    lw_xxtea_context *ctx = (lw_xxtea_context *) malloc(
            sizeof(lw_xxtea_context));
    if (ctx == NULL) {
        return NULL;
    }
    lw_xxtea_init(ctx);
    return ctx;
}

static void xxtea_ctx_free(void *ctx)
{
    lw_xxtea_free((lw_xxtea_context *) ctx);
    free(ctx);
}

static const lw_cipher_base_t xxtea_info = {
        LW_CIPHER_ID_XXTEA,
        xxtea_crypt_ecb_wrap,
        xxtea_crypt_cbc_wrap,
        xxtea_crypt_ctr_wrap,
        xxtea_setkey_enc_wrap,
        xxtea_setkey_dec_wrap,
        xxtea_ctx_alloc,
        xxtea_ctx_free
};

static const lw_cipher_info_t lw_cipher_xxtea_ecb_info = {
        "XXTEA-ECB",
        8,
        0,
        128,
        LW_MODE_ECB,
        LW_CIPHER_XXTEA_ECB,
        0,
        LW_CIPHER_BASE_INDEX_XXTEA
};

static const lw_cipher_info_t lw_cipher_xxtea_cbc_info = {
        "XXTEA-CBC",
        8,
        8,
        128,
        LW_MODE_CBC,
        LW_CIPHER_XXTEA_CBC,
        0,
        LW_CIPHER_BASE_INDEX_XXTEA
};

static const lw_cipher_info_t lw_cipher_xxtea_ctr_info = {
        "XXTEA-CTR",
        8,
        8,
        128,
        LW_MODE_CTR,
        LW_CIPHER_XXTEA_CTR,
        0,
        LW_CIPHER_BASE_INDEX_XXTEA
};

static int simon_crypt_ecb_wrap(void *ctx, lw_operation_t operation,
                                const uint8_t *input, uint8_t *output)
{
    return lw_simon_crypt_ecb((lw_simon_context *) ctx, operation, input,
                              output);
}

static int simon_crypt_cbc_wrap(void *ctx, lw_operation_t operation,
                                size_t length, uint8_t *iv,
                                const uint8_t *input, uint8_t *output)
{
    return lw_simon_crypt_cbc((lw_simon_context *) ctx, operation, length, iv,
                              input, output);
}

static int simon_crypt_ctr_wrap(void *ctx, size_t length, uint8_t *nc_off,
                                uint8_t *nonce_counter,
                                uint8_t *stream_block, const uint8_t *input,
                                uint8_t *output)
{
    return lw_simon_crypt_ctr((lw_simon_context *) ctx, length, nc_off,
                              nonce_counter, stream_block, input, output);
}

static int simon_setkey_enc_wrap(void *ctx, const uint8_t *key,
                                 unsigned int key_bitlen)
{
    return lw_simon_setkey((lw_simon_context *) ctx, key, key_bitlen);
}

static int simon_setkey_dec_wrap(void *ctx, const uint8_t *key,
                                 unsigned int key_bitlen)
{
    return lw_simon_setkey((lw_simon_context *) ctx, key, key_bitlen);
}

static void *simon_ctx_alloc(uint8_t block_size)
{
    lw_simon_context *ctx = (lw_simon_context *) malloc(
            sizeof(lw_simon_context));
    if (ctx == NULL) {
        return NULL;
    }
    lw_simon_init(ctx, block_size);
    return ctx;
}

static void simon_ctx_free(void *ctx)
{
    lw_simon_free((lw_simon_context *) ctx);
    free(ctx);
}

static const lw_cipher_base_t simon_info = {
        LW_CIPHER_ID_SIMON,
        simon_crypt_ecb_wrap,
        simon_crypt_cbc_wrap,
        simon_crypt_ctr_wrap,
        simon_setkey_enc_wrap,
        simon_setkey_dec_wrap,
        simon_ctx_alloc,
        simon_ctx_free
};

static const lw_cipher_info_t lw_cipher_simon_64_32_ecb_info = {
        "SIMON-64_32-ECB",
        4,
        0,
        64,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_64_32_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_64_32_cbc_info = {
        "SIMON-64_32-CBC",
        4,
        4,
        64,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_64_32_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_64_32_ctr_info = {
        "SIMON-64_32-CTR",
        4,
        4,
        64,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_64_32_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_72_48_ecb_info = {
        "SIMON-72_48-ECB",
        6,
        0,
        72,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_72_48_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_72_48_cbc_info = {
        "SIMON-72_48-CBC",
        6,
        6,
        72,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_72_48_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_72_48_ctr_info = {
        "SIMON-72_48-CTR",
        6,
        6,
        72,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_72_48_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_48_ecb_info = {
        "SIMON-96_48-ECB",
        6,
        0,
        96,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_96_48_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_48_cbc_info = {
        "SIMON-96_48-CBC",
        6,
        6,
        96,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_96_48_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_48_ctr_info = {
        "SIMON-96_48-CTR",
        6,
        6,
        96,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_96_48_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_64_ecb_info = {
        "SIMON-96_64-ECB",
        8,
        0,
        96,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_96_64_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_64_cbc_info = {
        "SIMON-96_64-CBC",
        8,
        8,
        96,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_96_64_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_64_ctr_info = {
        "SIMON-96_64-CTR",
        8,
        8,
        96,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_96_64_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_128_64_ecb_info = {
        "SIMON-128_64-ECB",
        8,
        0,
        128,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_128_64_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_128_64_cbc_info = {
        "SIMON-128_64-CBC",
        8,
        8,
        128,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_128_64_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_128_64_ctr_info = {
        "SIMON-128_64-CTR",
        8,
        8,
        128,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_128_64_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_96_ecb_info = {
        "SIMON-96_96-ECB",
        12,
        0,
        96,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_96_96_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_96_cbc_info = {
        "SIMON-96_96-CBC",
        12,
        12,
        96,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_96_96_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_96_96_ctr_info = {
        "SIMON-96_96-CTR",
        12,
        12,
        96,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_96_96_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_144_96_ecb_info = {
        "SIMON-144_96-ECB",
        12,
        0,
        144,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_144_96_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_144_96_cbc_info = {
        "SIMON-144_96-CBC",
        12,
        12,
        144,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_144_96_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_144_96_ctr_info = {
        "SIMON-144_96-CTR",
        12,
        12,
        144,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_144_96_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_128_128_ecb_info = {
        "SIMON-128_128-ECB",
        16,
        0,
        128,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_128_128_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_128_128_cbc_info = {
        "SIMON-128_128-CBC",
        16,
        16,
        128,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_128_128_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_128_128_ctr_info = {
        "SIMON-128_128-CTR",
        16,
        16,
        128,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_128_128_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_192_128_ecb_info = {
        "SIMON-192_128-ECB",
        16,
        0,
        192,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_192_128_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_192_128_cbc_info = {
        "SIMON-192_128-CBC",
        16,
        16,
        192,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_192_128_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_192_128_ctr_info = {
        "SIMON-192_128-CTR",
        16,
        16,
        192,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_192_128_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_256_128_ecb_info = {
        "SIMON-256_128-ECB",
        16,
        0,
        256,
        LW_MODE_ECB,
        LW_CIPHER_SIMON_256_128_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_256_128_cbc_info = {
        "SIMON-256_128-CBC",
        16,
        16,
        256,
        LW_MODE_CBC,
        LW_CIPHER_SIMON_256_128_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static const lw_cipher_info_t lw_cipher_simon_256_128_ctr_info = {
        "SIMON-256_128-CTR",
        16,
        16,
        256,
        LW_MODE_CTR,
        LW_CIPHER_SIMON_256_128_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SIMON
};

static int speck_crypt_ecb_wrap(void *ctx, lw_operation_t operation,
                                const uint8_t *input, uint8_t *output)
{
    return lw_speck_crypt_ecb((lw_speck_context *) ctx, operation, input,
                              output);
}

static int speck_crypt_cbc_wrap(void *ctx, lw_operation_t operation,
                                size_t length, uint8_t *iv,
                                const uint8_t *input, uint8_t *output)
{
    return lw_speck_crypt_cbc((lw_speck_context *) ctx, operation, length, iv,
                              input, output);
}

static int speck_crypt_ctr_wrap(void *ctx, size_t length, uint8_t *nc_off,
                                uint8_t *nonce_counter,
                                uint8_t *stream_block, const uint8_t *input,
                                uint8_t *output)
{
    return lw_speck_crypt_ctr((lw_speck_context *) ctx, length, nc_off,
                              nonce_counter, stream_block, input, output);
}

static int speck_setkey_enc_wrap(void *ctx, const uint8_t *key,
                                 unsigned int key_bitlen)
{
    return lw_speck_setkey((lw_speck_context *) ctx, key, key_bitlen);
}

static int speck_setkey_dec_wrap(void *ctx, const uint8_t *key,
                                 unsigned int key_bitlen)
{
    return lw_speck_setkey((lw_speck_context *) ctx, key, key_bitlen);
}

static void *speck_ctx_alloc(uint8_t block_size)
{
    lw_speck_context *ctx = (lw_speck_context *) malloc(
            sizeof(lw_speck_context));
    if (ctx == NULL) {
        return NULL;
    }
    lw_speck_init(ctx, block_size);
    return ctx;
}

static void speck_ctx_free(void *ctx)
{
    lw_speck_free((lw_speck_context *) ctx);
    free(ctx);
}

static const lw_cipher_base_t speck_info = {
        LW_CIPHER_ID_SPECK,
        speck_crypt_ecb_wrap,
        speck_crypt_cbc_wrap,
        speck_crypt_ctr_wrap,
        speck_setkey_enc_wrap,
        speck_setkey_dec_wrap,
        speck_ctx_alloc,
        speck_ctx_free
};

static const lw_cipher_info_t lw_cipher_speck_64_32_ecb_info = {
        "SPECK-64_32-ECB",
        4,
        0,
        64,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_64_32_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_64_32_cbc_info = {
        "SPECK-64_32-CBC",
        4,
        4,
        64,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_64_32_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_64_32_ctr_info = {
        "SPECK-64_32-CTR",
        4,
        4,
        64,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_64_32_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_72_48_ecb_info = {
        "SPECK-72_48-ECB",
        6,
        0,
        72,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_72_48_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_72_48_cbc_info = {
        "SPECK-72_48-CBC",
        6,
        6,
        72,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_72_48_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_72_48_ctr_info = {
        "SPECK-72_48-CTR",
        6,
        6,
        72,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_72_48_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_48_ecb_info = {
        "SPECK-96_48-ECB",
        6,
        0,
        96,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_96_48_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_48_cbc_info = {
        "SPECK-96_48-CBC",
        6,
        6,
        96,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_96_48_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_48_ctr_info = {
        "SPECK-96_48-CTR",
        6,
        6,
        96,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_96_48_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_64_ecb_info = {
        "SPECK-96_64-ECB",
        8,
        0,
        96,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_96_64_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_64_cbc_info = {
        "SPECK-96_64-CBC",
        8,
        8,
        96,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_96_64_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_64_ctr_info = {
        "SPECK-96_64-CTR",
        8,
        8,
        96,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_96_64_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_128_64_ecb_info = {
        "SPECK-128_64-ECB",
        8,
        0,
        128,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_128_64_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_128_64_cbc_info = {
        "SPECK-128_64-CBC",
        8,
        8,
        128,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_128_64_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_128_64_ctr_info = {
        "SPECK-128_64-CTR",
        8,
        8,
        128,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_128_64_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_96_ecb_info = {
        "SPECK-96_96-ECB",
        12,
        0,
        96,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_96_96_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_96_cbc_info = {
        "SPECK-96_96-CBC",
        12,
        12,
        96,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_96_96_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_96_96_ctr_info = {
        "SPECK-96_96-CTR",
        12,
        12,
        96,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_96_96_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_144_96_ecb_info = {
        "SPECK-144_96-ECB",
        12,
        0,
        144,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_144_96_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_144_96_cbc_info = {
        "SPECK-144_96-CBC",
        12,
        12,
        144,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_144_96_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_144_96_ctr_info = {
        "SPECK-144_96-CTR",
        12,
        12,
        144,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_144_96_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_128_128_ecb_info = {
        "SPECK-128_128-ECB",
        16,
        0,
        128,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_128_128_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_128_128_cbc_info = {
        "SPECK-128_128-CBC",
        16,
        16,
        128,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_128_128_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_128_128_ctr_info = {
        "SPECK-128_128-CTR",
        16,
        16,
        128,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_128_128_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_192_128_ecb_info = {
        "SPECK-192_128-ECB",
        16,
        0,
        192,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_192_128_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_192_128_cbc_info = {
        "SPECK-192_128-CBC",
        16,
        16,
        192,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_192_128_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_192_128_ctr_info = {
        "SPECK-192_128-CTR",
        16,
        16,
        192,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_192_128_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_256_128_ecb_info = {
        "SPECK-256_128-ECB",
        16,
        0,
        256,
        LW_MODE_ECB,
        LW_CIPHER_SPECK_256_128_ECB,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_256_128_cbc_info = {
        "SPECK-256_128-CBC",
        16,
        16,
        256,
        LW_MODE_CBC,
        LW_CIPHER_SPECK_256_128_CBC,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static const lw_cipher_info_t lw_cipher_speck_256_128_ctr_info = {
        "SPECK-256_128-CTR",
        16,
        16,
        256,
        LW_MODE_CTR,
        LW_CIPHER_SPECK_256_128_CTR,
        0,
        LW_CIPHER_BASE_INDEX_SPECK
};

static int present_crypt_ecb_wrap(void *ctx, lw_operation_t operation,
                                  const uint8_t *input, uint8_t *output)
{
    return lw_present_crypt_ecb((lw_present_context *) ctx, operation, input,
                                output);
}

static int present_crypt_cbc_wrap(void *ctx, lw_operation_t operation,
                                  size_t length, uint8_t *iv,
                                  const uint8_t *input, uint8_t *output)
{
    return lw_present_crypt_cbc((lw_present_context *) ctx, operation, length,
                                iv, input, output);
}

static int present_crypt_ctr_wrap(void *ctx, size_t length, uint8_t *nc_off,
                                  uint8_t *nonce_counter,
                                  uint8_t *stream_block, const uint8_t *input,
                                  uint8_t *output)
{
    return lw_present_crypt_ctr((lw_present_context *) ctx, length, nc_off,
                                nonce_counter, stream_block, input, output);
}

static int present_setkey_enc_wrap(void *ctx, const uint8_t *key,
                                   unsigned int key_bitlen)
{
    return lw_present_setkey((lw_present_context *) ctx, key, key_bitlen);
}

static int present_setkey_dec_wrap(void *ctx, const uint8_t *key,
                                   unsigned int key_bitlen)
{
    return lw_present_setkey((lw_present_context *) ctx, key, key_bitlen);
}

static void *present_ctx_alloc(uint8_t block_size)
{
    lw_present_context *ctx = (lw_present_context *) malloc(
            sizeof(lw_present_context));
    if (ctx == NULL) {
        return NULL;
    }
    lw_present_init(ctx);
    return ctx;
}

static void present_ctx_free(void *ctx)
{
    lw_present_free((lw_present_context *) ctx);
    free(ctx);
}

static const lw_cipher_base_t present_info = {
        LW_CIPHER_ID_PRESENT,
        present_crypt_ecb_wrap,
        present_crypt_cbc_wrap,
        present_crypt_ctr_wrap,
        present_setkey_enc_wrap,
        present_setkey_dec_wrap,
        present_ctx_alloc,
        present_ctx_free
};

static const lw_cipher_info_t lw_cipher_present_80_ecb_info = {
        "PRESENT-80-ECB",
        8,
        0,
        80,
        LW_MODE_ECB,
        LW_CIPHER_PRESENT_80_ECB,
        0,
        LW_CIPHER_BASE_INDEX_PRESENT
};

static const lw_cipher_info_t lw_cipher_present_80_cbc_info = {
        "PRESENT-80-CBC",
        8,
        8,
        80,
        LW_MODE_CBC,
        LW_CIPHER_PRESENT_80_CBC,
        0,
        LW_CIPHER_BASE_INDEX_PRESENT
};

static const lw_cipher_info_t lw_cipher_present_80_ctr_info = {
        "PRESENT-80-CTR",
        8,
        8,
        80,
        LW_MODE_CTR,
        LW_CIPHER_PRESENT_80_CTR,
        0,
        LW_CIPHER_BASE_INDEX_PRESENT
};

static const lw_cipher_info_t lw_cipher_present_128_ecb_info = {
        "PRESENT-128-ECB",
        8,
        0,
        128,
        LW_MODE_ECB,
        LW_CIPHER_PRESENT_128_ECB,
        0,
        LW_CIPHER_BASE_INDEX_PRESENT
};

static const lw_cipher_info_t lw_cipher_present_128_cbc_info = {
        "PRESENT-128-CBC",
        8,
        8,
        128,
        LW_MODE_CBC,
        LW_CIPHER_PRESENT_128_CBC,
        0,
        LW_CIPHER_BASE_INDEX_PRESENT
};

static const lw_cipher_info_t lw_cipher_present_128_ctr_info = {
        "PRESENT-128-CTR",
        8,
        8,
        128,
        LW_MODE_CTR,
        LW_CIPHER_PRESENT_128_CTR,
        0,
        LW_CIPHER_BASE_INDEX_PRESENT
};

const lw_cipher_definition_t lw_cipher_definitions[] = {
        {LW_CIPHER_XTEA_ECB,&lw_cipher_xtea_ecb_info},
        {LW_CIPHER_XTEA_CBC,&lw_cipher_xtea_cbc_info},
        {LW_CIPHER_XTEA_CTR,&lw_cipher_xtea_ctr_info},
        {LW_CIPHER_XXTEA_ECB,&lw_cipher_xxtea_ecb_info},
        {LW_CIPHER_XXTEA_CBC,&lw_cipher_xxtea_cbc_info},
        {LW_CIPHER_XXTEA_CTR,&lw_cipher_xxtea_ctr_info},
        {LW_CIPHER_SIMON_64_32_ECB,&lw_cipher_simon_64_32_ecb_info},
        {LW_CIPHER_SIMON_64_32_CBC,&lw_cipher_simon_64_32_cbc_info},
        {LW_CIPHER_SIMON_64_32_CTR,&lw_cipher_simon_64_32_ctr_info},
        {LW_CIPHER_SIMON_72_48_ECB,&lw_cipher_simon_72_48_ecb_info},
        {LW_CIPHER_SIMON_72_48_CBC,&lw_cipher_simon_72_48_cbc_info},
        {LW_CIPHER_SIMON_72_48_CTR,&lw_cipher_simon_72_48_ctr_info},
        {LW_CIPHER_SIMON_96_48_ECB,&lw_cipher_simon_96_48_ecb_info},
        {LW_CIPHER_SIMON_96_48_CBC,&lw_cipher_simon_96_48_cbc_info},
        {LW_CIPHER_SIMON_96_48_CTR,&lw_cipher_simon_96_48_ctr_info},
        {LW_CIPHER_SIMON_96_64_ECB,&lw_cipher_simon_96_64_ecb_info},
        {LW_CIPHER_SIMON_96_64_CBC,&lw_cipher_simon_96_64_cbc_info},
        {LW_CIPHER_SIMON_96_64_CTR,&lw_cipher_simon_96_64_ctr_info},
        {LW_CIPHER_SIMON_128_64_ECB,&lw_cipher_simon_128_64_ecb_info},
        {LW_CIPHER_SIMON_128_64_CBC,&lw_cipher_simon_128_64_cbc_info},
        {LW_CIPHER_SIMON_128_64_CTR,&lw_cipher_simon_128_64_ctr_info},
        {LW_CIPHER_SIMON_96_96_ECB,&lw_cipher_simon_96_96_ecb_info},
        {LW_CIPHER_SIMON_96_96_CBC,&lw_cipher_simon_96_96_cbc_info},
        {LW_CIPHER_SIMON_96_96_CTR,&lw_cipher_simon_96_96_ctr_info},
        {LW_CIPHER_SIMON_144_96_ECB,&lw_cipher_simon_144_96_ecb_info},
        {LW_CIPHER_SIMON_144_96_CBC,&lw_cipher_simon_144_96_cbc_info},
        {LW_CIPHER_SIMON_144_96_CTR,&lw_cipher_simon_144_96_ctr_info},
        {LW_CIPHER_SIMON_128_128_ECB,&lw_cipher_simon_128_128_ecb_info},
        {LW_CIPHER_SIMON_128_128_CBC,&lw_cipher_simon_128_128_cbc_info},
        {LW_CIPHER_SIMON_128_128_CTR,&lw_cipher_simon_128_128_ctr_info},
        {LW_CIPHER_SIMON_192_128_ECB,&lw_cipher_simon_192_128_ecb_info},
        {LW_CIPHER_SIMON_192_128_CBC,&lw_cipher_simon_192_128_cbc_info},
        {LW_CIPHER_SIMON_192_128_CTR,&lw_cipher_simon_192_128_ctr_info},
        {LW_CIPHER_SIMON_256_128_ECB,&lw_cipher_simon_256_128_ecb_info},
        {LW_CIPHER_SIMON_256_128_CBC,&lw_cipher_simon_256_128_cbc_info},
        {LW_CIPHER_SIMON_256_128_CTR,&lw_cipher_simon_256_128_ctr_info},
        {LW_CIPHER_SPECK_64_32_ECB,&lw_cipher_speck_64_32_ecb_info},
        {LW_CIPHER_SPECK_64_32_CBC,&lw_cipher_speck_64_32_cbc_info},
        {LW_CIPHER_SPECK_64_32_CTR,&lw_cipher_speck_64_32_ctr_info},
        {LW_CIPHER_SPECK_72_48_ECB,&lw_cipher_speck_72_48_ecb_info},
        {LW_CIPHER_SPECK_72_48_CBC,&lw_cipher_speck_72_48_cbc_info},
        {LW_CIPHER_SPECK_72_48_CTR,&lw_cipher_speck_72_48_ctr_info},
        {LW_CIPHER_SPECK_96_48_ECB,&lw_cipher_speck_96_48_ecb_info},
        {LW_CIPHER_SPECK_96_48_CBC,&lw_cipher_speck_96_48_cbc_info},
        {LW_CIPHER_SPECK_96_48_CTR,&lw_cipher_speck_96_48_ctr_info},
        {LW_CIPHER_SPECK_96_64_ECB,&lw_cipher_speck_96_64_ecb_info},
        {LW_CIPHER_SPECK_96_64_CBC,&lw_cipher_speck_96_64_cbc_info},
        {LW_CIPHER_SPECK_96_64_CTR,&lw_cipher_speck_96_64_ctr_info},
        {LW_CIPHER_SPECK_128_64_ECB,&lw_cipher_speck_128_64_ecb_info},
        {LW_CIPHER_SPECK_128_64_CBC,&lw_cipher_speck_128_64_cbc_info},
        {LW_CIPHER_SPECK_128_64_CTR,&lw_cipher_speck_128_64_ctr_info},
        {LW_CIPHER_SPECK_96_96_ECB,&lw_cipher_speck_96_96_ecb_info},
        {LW_CIPHER_SPECK_96_96_CBC,&lw_cipher_speck_96_96_cbc_info},
        {LW_CIPHER_SPECK_96_96_CTR,&lw_cipher_speck_96_96_ctr_info},
        {LW_CIPHER_SPECK_144_96_ECB,&lw_cipher_speck_144_96_ecb_info},
        {LW_CIPHER_SPECK_144_96_CBC,&lw_cipher_speck_144_96_cbc_info},
        {LW_CIPHER_SPECK_144_96_CTR,&lw_cipher_speck_144_96_ctr_info},
        {LW_CIPHER_SPECK_128_128_ECB,&lw_cipher_speck_128_128_ecb_info},
        {LW_CIPHER_SPECK_128_128_CBC,&lw_cipher_speck_128_128_cbc_info},
        {LW_CIPHER_SPECK_128_128_CTR,&lw_cipher_speck_128_128_ctr_info},
        {LW_CIPHER_SPECK_192_128_ECB,&lw_cipher_speck_192_128_ecb_info},
        {LW_CIPHER_SPECK_192_128_CBC,&lw_cipher_speck_192_128_cbc_info},
        {LW_CIPHER_SPECK_192_128_CTR,&lw_cipher_speck_192_128_ctr_info},
        {LW_CIPHER_SPECK_256_128_ECB,&lw_cipher_speck_256_128_ecb_info},
        {LW_CIPHER_SPECK_256_128_CBC,&lw_cipher_speck_256_128_cbc_info},
        {LW_CIPHER_SPECK_256_128_CTR,&lw_cipher_speck_256_128_ctr_info},
        {LW_CIPHER_PRESENT_80_ECB,&lw_cipher_present_80_ecb_info},
        {LW_CIPHER_PRESENT_80_CBC,&lw_cipher_present_80_cbc_info},
        {LW_CIPHER_PRESENT_80_CTR,&lw_cipher_present_80_ctr_info},
        {LW_CIPHER_PRESENT_128_ECB,&lw_cipher_present_128_ecb_info},
        {LW_CIPHER_PRESENT_128_CBC,&lw_cipher_present_128_cbc_info},
        {LW_CIPHER_PRESENT_128_CTR,&lw_cipher_present_128_ctr_info}
};

//const lw_cipher_base_t *lw_cipher_base_lookup_table[] = {
//        [LW_CIPHER_BASE_INDEX_XTEA] = &xtea_info,
//        [LW_CIPHER_BASE_INDEX_XXTEA] = &xxtea_info,
//        [LW_CIPHER_BASE_INDEX_SIMON] = &simon_info,
//        [LW_CIPHER_BASE_INDEX_SPECK] = &speck_info,
//        [LW_CIPHER_BASE_INDEX_PRESENT] = &present_info
//};

const lw_cipher_base_t *lw_cipher_base_lookup_table[] = {
        &xtea_info,
        &xxtea_info,
        &simon_info,
        &speck_info,
        &present_info
};