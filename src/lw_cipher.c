#include "lwcipher.h"
#include "lw_cipher_wrapper.h"
#include <string.h>
#include <stdlib.h>

static inline const lw_cipher_base_t *lw_cipher_get_base(const lw_cipher_info_t *info)
{
    return lw_cipher_base_lookup_table[info->base_idx];
}

const lw_cipher_info_t *lw_cipher_info_from_type(const lw_cipher_type_t cipher_type)
{
    const lw_cipher_definition_t *def;

    for (def = lw_cipher_definitions; def->info != NULL; def++) {
        if (def->type == cipher_type) {
            return def->info;
        }
    }
    return NULL;
}

const lw_cipher_info_t *lw_cipher_info_from_string(const char *cipher_name)
{
    const lw_cipher_definition_t *def;
    if (NULL == cipher_name) {
        return NULL;
    }

    for (def = lw_cipher_definitions; def->info != NULL; def++) {
        if (!strcmp(def->info->name, cipher_name)) {
            return def->info;
        }
    }
    return NULL;
}

const lw_cipher_info_t *
lw_cipher_info_from_values(const lw_cipher_id_t cipher_id, int key_bitlen, const lw_cipher_mode_t cipher_mode)
{
    const lw_cipher_definition_t *def;

    for (def = lw_cipher_definitions; def->info != NULL; def++) {
        if (lw_cipher_get_base(def->info)->cipher == cipher_id &&
            lw_cipher_info_get_key_bitlen((lw_cipher_info_t *)(def->info)) == (unsigned) key_bitlen &&
            def->info->mode == cipher_mode) {
            return def->info;
        }
    }
    return NULL;
}

void lw_cipher_init(lw_cipher_context_t *ctx)
{
    memset(ctx, 0, sizeof(lw_cipher_context_t));
    ctx->cipher_info = (lw_cipher_info_t*) malloc(sizeof(lw_cipher_info_t));
}

void lw_cipher_free(lw_cipher_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->cipher_ctx) {
        lw_cipher_get_base(ctx->cipher_info)->ctx_free_func(ctx->cipher_ctx);
    }
    free(ctx->cipher_info);
    ctx->cipher_info = NULL;
    memset(ctx, 0, sizeof(lw_cipher_context_t));
}

int lw_cipher_setup(lw_cipher_context_t *ctx, const lw_cipher_info_t *cipher_info)
{
    if (cipher_info == NULL) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (NULL == (ctx->cipher_ctx = lw_cipher_get_base(cipher_info)->ctx_alloc_func(cipher_info->block_size))) {
        return LW_ERR_CIPHER_ALLOC_FAILED;
    }
    memcpy(ctx->cipher_info, cipher_info, sizeof(lw_cipher_info_t))  ;
    return 0;
}

int lw_cipher_setkey(lw_cipher_context_t *ctx, const uint8_t *key, unsigned int key_bitlen,
                     const lw_operation_t operation)
{
    if (operation != LW_ENCRYPT && operation != LW_DECRYPT) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }
    if (ctx->cipher_info == NULL) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

    if (operation == LW_ENCRYPT || LW_MODE_CTR == ((lw_cipher_mode_t) ctx->cipher_info->mode))
        return lw_cipher_get_base(ctx->cipher_info)->setkey_enc_func(ctx->cipher_ctx, key,
                                                                     ctx->key_bitlen);
    if (LW_DECRYPT == operation) {
        return lw_cipher_get_base(ctx->cipher_info)->setkey_dec_func(ctx->cipher_ctx, key,
                                                                     ctx->key_bitlen);
    }
    return LW_ERR_CIPHER_BAD_INPUT_DATA;
}

int lw_cipher_set_iv(lw_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len)
{
    uint16_t actual_iv_size;
    if (ctx->cipher_info == NULL) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }
    /* avoid buffer overflow in ctx->iv */
    if (iv_len > LW_MAX_IV_LENGTH) {
        return LW_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
    lw_cipher_info_get_iv_size(ctx->cipher_info);
    actual_iv_size = lw_cipher_info_get_iv_size(ctx->cipher_info);
    /* avoid reading past the end of input buffer */
    if (actual_iv_size > iv_len) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (actual_iv_size != 0) {
        memcpy(ctx->iv, iv, actual_iv_size);
        ctx->iv_size = actual_iv_size;
    }
    return 0;
}

int lw_cipher_reset(lw_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }
    ctx->unprocessed_len = 0;
    return 0;
}

int lw_cipher_update(lw_cipher_context_t *ctx, const unsigned char *input, size_t ilen, unsigned char *output,
                     size_t *olen)
{
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    size_t block_size;

    if (ctx->cipher_info == NULL) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }

    *olen = 0;
    block_size = lw_cipher_get_block_size(ctx);
    if (0 == block_size) {
        return LW_ERR_CIPHER_INVALID_CONTEXT;
    }

    if (((lw_cipher_mode_t) ctx->cipher_info->mode) == LW_MODE_ECB) {
        if (ilen != block_size) {
            return LW_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }
        *olen = ilen;
        if (0 != (ret = lw_cipher_get_base(ctx->cipher_info)->ecb_func(ctx->cipher_ctx,
                                                                       ctx->operation, input,
                                                                       output))) {
            return ret;
        }
        return 0;
    }


    if (input == output &&
        (ctx->unprocessed_len != 0 || ilen % block_size)) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (((lw_cipher_mode_t) ctx->cipher_info->mode) == LW_MODE_CBC) {
        int copy_len = 0;
        /*
         * If there is not enough data for a full block, cache it.
         */
        if ((ctx->operation == LW_DECRYPT && NULL != ctx->add_padding &&
             ilen <= block_size - ctx->unprocessed_len) ||
            (ctx->operation == LW_DECRYPT && NULL == ctx->add_padding &&
             ilen < block_size - ctx->unprocessed_len) ||
            (ctx->operation == LW_ENCRYPT &&
             ilen < block_size - ctx->unprocessed_len)) {
            memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]), input,
                   ilen);
            ctx->unprocessed_len += ilen;
            return 0;
        }

        /*
         * Process cached data first
         */
        if (0 != ctx->unprocessed_len) {
            copy_len = block_size - ctx->unprocessed_len;

            memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]), input,
                   copy_len);

            if (0 != (ret = lw_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                           ctx->operation,
                                                                           block_size, ctx->iv,
                                                                           ctx->unprocessed_data,
                                                                           output))) {
                return ret;
            }
            *olen += block_size;
            output += block_size;
            ctx->unprocessed_len = 0;
            input += copy_len;
            ilen -= copy_len;
        }
        /*
     * Cache final, incomplete block
     */
        if (0 != ilen) {
            /* Encryption: only cache partial blocks
             * Decryption w/ padding: always keep at least one whole block
             * Decryption w/o padding: only cache partial blocks
             */
            copy_len = ilen % block_size;
            if (copy_len == 0 &&
                ctx->operation == LW_DECRYPT &&
                NULL != ctx->add_padding) {
                copy_len = block_size;
            }

            memcpy(ctx->unprocessed_data, &(input[ilen - copy_len]),
                   copy_len);

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if (ilen) {
            if (0 != (ret = lw_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                           ctx->operation,
                                                                           ilen, ctx->iv,
                                                                           input,
                                                                           output))) {
                return ret;
            }

            *olen += ilen;
        }
    }
    if (((lw_cipher_mode_t) ctx->cipher_info->mode) == LW_MODE_CTR) {
        if (0 != (ret = lw_cipher_get_base(ctx->cipher_info)->ctr_func(ctx->cipher_ctx,
                                                                       ilen,
                                                                       (uint8_t *) &ctx->unprocessed_len,
                                                                       ctx->iv,
                                                                       ctx->unprocessed_data,
                                                                       input, output))) {
            return ret;
        }
        *olen = ilen;
        return 0;
    }
    return 0;
}


int lw_cipher_finish(lw_cipher_context_t *ctx, unsigned char *output, size_t *olen)
{
    if (ctx->cipher_info == NULL) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }
    *olen = 0;
    if (LW_MODE_CTR == ((lw_cipher_mode_t) ctx->cipher_info->mode)) {
        return 0;
    }
    if (LW_MODE_ECB == ((lw_cipher_mode_t) ctx->cipher_info->mode)) {
        if (ctx->unprocessed_len != 0) {
            return LW_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }
        return 0;
    }
    if (LW_MODE_CBC == ((lw_cipher_mode_t) ctx->cipher_info->mode)) {
        int ret = 0;

        if (LW_ENCRYPT == ctx->operation) {
            /* check for 'no padding' mode */
            if (NULL == ctx->add_padding) {
                if (0 != ctx->unprocessed_len) {
                    return LW_ERR_CIPHER_FULL_BLOCK_EXPECTED;
                }
                return 0;
            }

            ctx->add_padding(ctx->unprocessed_data, lw_cipher_get_iv_size(ctx),
                             ctx->unprocessed_len);
        } else if (lw_cipher_get_block_size(ctx) != ctx->unprocessed_len) {
            /*
             * For decrypt operations, expect a full block,
             * or an empty block if no padding
             */
            if (NULL == ctx->add_padding && 0 == ctx->unprocessed_len) {
                return 0;
            }
            return LW_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        /* cipher block */
        if (0 != (ret = lw_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                       ctx->operation,
                                                                       lw_cipher_get_block_size(
                                                                               ctx),
                                                                       ctx->iv,
                                                                       ctx->unprocessed_data,
                                                                       output))) {
            return ret;
        }
        /* Set output size for decryption */
        if (LW_DECRYPT == ctx->operation) {
            return ctx->get_padding(output, lw_cipher_get_block_size(ctx),
                                    olen);
        }
        /* Set output size for encryption */
        *olen = lw_cipher_get_block_size(ctx);
        return 0;
    }
    return LW_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

/*
 * PKCS7 (and PKCS5) padding: fill with ll bytes, with ll = padding_len
 */
static void add_pkcs_padding(unsigned char *output, size_t output_len,
                             size_t data_len)
{
    size_t padding_len = output_len - data_len;
    unsigned char i;

    for (i = 0; i < padding_len; i++) {
        output[data_len + i] = (unsigned char) padding_len;
    }
}

static int get_pkcs_padding(unsigned char *input, size_t input_len,
                            size_t *data_len)
{
    size_t i, pad_idx;
    unsigned char padding_len;

    if (NULL == input || NULL == data_len) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    size_t bad = padding_len > input_len;
    bad = (bad | (padding_len == 0));

    /* The number of bytes checked must be independent of padding_len,
     * so pick input_len, which is usually 8 or 16 (one block) */
    pad_idx = input_len - padding_len;
    for (i = 0; i < input_len; i++) {
        size_t in_padding = (i >= pad_idx);
        size_t different = (input[i] != padding_len);
        bad = (bad | (in_padding & different));
    }
    return -((int) (bad & (-LW_ERR_CIPHER_INVALID_PADDING)));
}

/*
 * No padding: don't pad :)
 *
 * There is no add_padding function (check for NULL in lw_cipher_finish)
 * but a trivial get_padding function
 */
static int get_no_padding(unsigned char *input, size_t input_len,
                          size_t *data_len)
{
    if (NULL == input || NULL == data_len) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }

    *data_len = input_len;

    return 0;
}

int lw_cipher_set_padding_mode(lw_cipher_context_t *ctx, lw_cipher_padding_t mode)
{
    if (NULL == ctx->cipher_info ||
        LW_MODE_CBC != ((lw_cipher_mode_t) ctx->cipher_info->mode)) {
        return LW_ERR_CIPHER_BAD_INPUT_DATA;
    }
    switch (mode) {
        case LW_CIPHER_PADDING_PKCS7:
            ctx->add_padding = add_pkcs_padding;
            ctx->get_padding = get_pkcs_padding;
            break;
        case LW_CIPHER_PADDING_NONE:
            ctx->add_padding = NULL;
            ctx->get_padding = get_no_padding;
            break;
        default:
            return LW_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
    return 0;
}

int lw_cipher_crypt(lw_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *input,
                    size_t ilen, unsigned char *output, size_t *olen)
{
    int ret = LW_ERR_ERROR_CORRUPTION_DETECTED;
    size_t finish_olen;

    if ((ret = lw_cipher_set_iv(ctx, iv, iv_len)) != 0) {
        return ret;
    }

    if ((ret = lw_cipher_reset(ctx)) != 0) {
        return ret;
    }

    if ((ret = lw_cipher_update(ctx, input, ilen,
                                output, olen)) != 0) {
        return ret;
    }

    if ((ret = lw_cipher_finish(ctx, output + *olen,
                                &finish_olen)) != 0) {
        return ret;
    }

    *olen += finish_olen;

    return 0;
}
