#ifndef LWCIPHER_LWCIPHER_H
#define LWCIPHER_LWCIPHER_H

#include <stdint.h>
#include "xtea.h"
#include "xxtea.h"
#include "simon.h"
#include "speck.h"
#include "present.h"

#ifdef __cplusplus
extern "C" {
#endif


/** The selected feature is not available. */
#define LW_ERR_CIPHER_FEATURE_UNAVAILABLE  (-0x6080)
/** Bad input parameters. */
#define LW_ERR_CIPHER_BAD_INPUT_DATA       (-0x6100)
/** Failed to allocate memory. */
#define LW_ERR_CIPHER_ALLOC_FAILED         (-0x6180)
/** Input data contains invalid padding and is rejected. */
#define LW_ERR_CIPHER_INVALID_PADDING      (-0x6200)
/** Decryption of block requires a full block. */
#define LW_ERR_CIPHER_FULL_BLOCK_EXPECTED  (-0x6280)
/** Authentication failed (for AEAD modes). */
#define LW_ERR_CIPHER_AUTH_FAILED          (-0x6300)
/** The context is invalid. For example, because it was freed. */
#define LW_ERR_CIPHER_INVALID_CONTEXT      (-0x6380)

typedef enum lw_cipher_id_t
{
    LW_CIPHER_ID_NONE = 0,
    LW_CIPHER_ID_NULL,
    LW_CIPHER_ID_XTEA,
    LW_CIPHER_ID_XXTEA,
    LW_CIPHER_ID_SIMON,
    LW_CIPHER_ID_SPECK,
    LW_CIPHER_ID_PRESENT
} lw_cipher_id_t;

typedef enum
{
    LW_CIPHER_NONE = 0,
    LW_CIPHER_NULL,
    LW_CIPHER_XTEA_ECB,
    LW_CIPHER_XTEA_CBC,
    LW_CIPHER_XTEA_CTR,
    LW_CIPHER_XXTEA_ECB,
    LW_CIPHER_XXTEA_CBC,
    LW_CIPHER_XXTEA_CTR,
    LW_CIPHER_SIMON_64_32_ECB,
    LW_CIPHER_SIMON_64_32_CBC,
    LW_CIPHER_SIMON_64_32_CTR,
    LW_CIPHER_SIMON_72_48_ECB,
    LW_CIPHER_SIMON_72_48_CBC,
    LW_CIPHER_SIMON_72_48_CTR,
    LW_CIPHER_SIMON_96_48_ECB,
    LW_CIPHER_SIMON_96_48_CBC,
    LW_CIPHER_SIMON_96_48_CTR,
    LW_CIPHER_SIMON_96_64_ECB,
    LW_CIPHER_SIMON_96_64_CBC,
    LW_CIPHER_SIMON_96_64_CTR,
    LW_CIPHER_SIMON_128_64_ECB,
    LW_CIPHER_SIMON_128_64_CBC,
    LW_CIPHER_SIMON_128_64_CTR,
    LW_CIPHER_SIMON_96_96_ECB,
    LW_CIPHER_SIMON_96_96_CBC,
    LW_CIPHER_SIMON_96_96_CTR,
    LW_CIPHER_SIMON_144_96_ECB,
    LW_CIPHER_SIMON_144_96_CBC,
    LW_CIPHER_SIMON_144_96_CTR,
    LW_CIPHER_SIMON_128_128_ECB,
    LW_CIPHER_SIMON_128_128_CBC,
    LW_CIPHER_SIMON_128_128_CTR,
    LW_CIPHER_SIMON_192_128_ECB,
    LW_CIPHER_SIMON_192_128_CBC,
    LW_CIPHER_SIMON_192_128_CTR,
    LW_CIPHER_SIMON_256_128_ECB,
    LW_CIPHER_SIMON_256_128_CBC,
    LW_CIPHER_SIMON_256_128_CTR,
    LW_CIPHER_SPECK_64_32_ECB,
    LW_CIPHER_SPECK_64_32_CBC,
    LW_CIPHER_SPECK_64_32_CTR,
    LW_CIPHER_SPECK_72_48_ECB,
    LW_CIPHER_SPECK_72_48_CBC,
    LW_CIPHER_SPECK_72_48_CTR,
    LW_CIPHER_SPECK_96_48_ECB,
    LW_CIPHER_SPECK_96_48_CBC,
    LW_CIPHER_SPECK_96_48_CTR,
    LW_CIPHER_SPECK_96_64_ECB,
    LW_CIPHER_SPECK_96_64_CBC,
    LW_CIPHER_SPECK_96_64_CTR,
    LW_CIPHER_SPECK_128_64_ECB,
    LW_CIPHER_SPECK_128_64_CBC,
    LW_CIPHER_SPECK_128_64_CTR,
    LW_CIPHER_SPECK_96_96_ECB,
    LW_CIPHER_SPECK_96_96_CBC,
    LW_CIPHER_SPECK_96_96_CTR,
    LW_CIPHER_SPECK_144_96_ECB,
    LW_CIPHER_SPECK_144_96_CBC,
    LW_CIPHER_SPECK_144_96_CTR,
    LW_CIPHER_SPECK_128_128_ECB,
    LW_CIPHER_SPECK_128_128_CBC,
    LW_CIPHER_SPECK_128_128_CTR,
    LW_CIPHER_SPECK_192_128_ECB,
    LW_CIPHER_SPECK_192_128_CBC,
    LW_CIPHER_SPECK_192_128_CTR,
    LW_CIPHER_SPECK_256_128_ECB,
    LW_CIPHER_SPECK_256_128_CBC,
    LW_CIPHER_SPECK_256_128_CTR,
    LW_CIPHER_PRESENT_80_ECB,
    LW_CIPHER_PRESENT_80_CBC,
    LW_CIPHER_PRESENT_80_CTR,
    LW_CIPHER_PRESENT_128_ECB,
    LW_CIPHER_PRESENT_128_CBC,
    LW_CIPHER_PRESENT_128_CTR,
} lw_cipher_type_t;

typedef enum
{
    LW_MODE_NONE = 0,
    LW_MODE_ECB,
    LW_MODE_CBC,
    LW_MODE_CTR
} lw_cipher_mode_t;

typedef enum
{
    LW_CIPHER_PADDING_PKCS7 = 0,     /**< PKCS7 padding (default).        */
    LW_CIPHER_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
    LW_CIPHER_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
    LW_CIPHER_PADDING_ZEROS,         /**< Zero padding (not reversible). */
    LW_CIPHER_PADDING_NONE,          /**< Never pad (full blocks only).   */
} lw_cipher_padding_t;

typedef enum
{
    LW_OPERATION_NONE = -1,
    LW_ENCRYPT,
    LW_DECRYPT
} lw_operation_t;

#define LW_MAX_IV_LENGTH      16
#define LW_MAX_BLOCK_LENGTH   16
#define LW_MAX_KEY_LENGTH     32
typedef struct lw_cipher_info_t
{
    const char *name;
    uint8_t block_size;
    uint8_t iv_size;
    uint16_t key_bitlen;
    uint8_t mode; // for example: LW_MODE_ECB
    uint8_t type; // for example: LW_CIPHER_XTEA_ECB
    uint8_t flags;
    uint8_t base_idx;
} lw_cipher_info_t;

typedef struct lw_cipher_context_t
{
    lw_cipher_info_t *cipher_info;
    int key_bitlen;
    lw_operation_t operation;

//    lw_cipher_padding_t padding;
    void (*add_padding)(unsigned char *output, size_t olen, size_t data_len);

    int (*get_padding)(unsigned char *input, size_t ilen, size_t *data_len);

    uint8_t unprocessed_data[LW_MAX_BLOCK_LENGTH];
    size_t unprocessed_len;
    uint8_t iv[LW_MAX_IV_LENGTH];
    size_t iv_size;
    void *cipher_ctx;//specific cipher context
} lw_cipher_context_t;

const lw_cipher_info_t *lw_cipher_info_from_type(const lw_cipher_type_t cipher_type);

const lw_cipher_info_t *lw_cipher_info_from_string(const char *cipher_name);

const lw_cipher_info_t *lw_cipher_info_from_values(const lw_cipher_id_t cipher_id,
                                                   int key_bitlen,
                                                   const lw_cipher_mode_t cipher_mode
);

static inline lw_cipher_type_t lw_cipher_info_get_type(
        const lw_cipher_info_t *info)
{
    if (info == NULL) {
        return LW_CIPHER_NONE;
    } else {
        return (lw_cipher_type_t) info->type;
    }
}

static inline lw_cipher_mode_t lw_cipher_info_get_mode(
        const lw_cipher_info_t *info)
{
    if (info == NULL) {
        return LW_MODE_NONE;
    } else {
        return (lw_cipher_mode_t) info->mode;
    }
}

static inline size_t lw_cipher_info_get_key_bitlen(
        lw_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    } else {
        return info->key_bitlen;
    }
}

static inline const char *lw_cipher_info_get_name(
        const lw_cipher_info_t *info)
{
    if (info == NULL) {
        return NULL;
    } else {
        return info->name;
    }
}

static inline size_t lw_cipher_info_get_iv_size(
        const lw_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    }

    return ((size_t) info->iv_size);
}

static inline size_t lw_cipher_info_get_block_size(
        const lw_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    }

    return (size_t) (info->block_size);
}

void lw_cipher_init(lw_cipher_context_t *ctx);

void lw_cipher_free(lw_cipher_context_t *ctx);

int lw_cipher_setup(lw_cipher_context_t *ctx, const lw_cipher_info_t *cipher_info);

static inline unsigned int lw_cipher_get_block_size(
        const lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return 0;
    }

    return (unsigned int) ctx->cipher_info->block_size;
}

static inline lw_cipher_mode_t lw_cipher_get_cipher_mode(
        const lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return LW_MODE_NONE;
    }

    return (lw_cipher_mode_t) ctx->cipher_info->mode;
}

static inline int lw_cipher_get_iv_size(
        const lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return 0;
    }

    if (ctx->iv_size != 0) {
        return (int) ctx->iv_size;
    }

    return (int) (((int) ctx->cipher_info->iv_size));
}

static inline lw_cipher_type_t lw_cipher_get_type(
        const lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return LW_CIPHER_NONE;
    }

    return (lw_cipher_type_t) ctx->cipher_info->type;
}

static inline const char *lw_cipher_get_name(
        const lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return 0;
    }

    return ctx->cipher_info->name;
}

static inline int lw_cipher_get_key_bitlen(
        const lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return 0;
    }

    return (int) ctx->cipher_info->key_bitlen;
}

static inline lw_operation_t lw_cipher_get_operation(
        const lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return LW_OPERATION_NONE;
    }

    return ctx->operation;
}


int lw_cipher_setkey(lw_cipher_context_t *ctx, const uint8_t *key,
                     unsigned int key_bitlen, const lw_operation_t operation);

int lw_cipher_set_padding_mode(lw_cipher_context_t *ctx,
                                    lw_cipher_padding_t mode);

int lw_cipher_set_iv(lw_cipher_context_t *ctx, const unsigned char *iv,
                     size_t iv_len);

int lw_cipher_reset(lw_cipher_context_t *ctx);

int lw_cipher_update(lw_cipher_context_t *ctx, const unsigned char *input,
                     size_t ilen, unsigned char *output, size_t *olen);

int lw_cipher_finish(lw_cipher_context_t *ctx,
                          unsigned char *output, size_t *olen);

int lw_cipher_crypt(lw_cipher_context_t *ctx,
                    const unsigned char *iv, size_t iv_len,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen);

#ifdef __cplusplus
}
#endif

#endif //LWCIPHER_LWCIPHER_H