#ifndef LWCIPHER_LW_CIPHER_WRAPPER_H
#define LWCIPHER_LW_CIPHER_WRAPPER_H
#include "lwcipher.h"
typedef struct lw_cipher_base_t {
    lw_cipher_id_t cipher;
    int (*ecb_func)(void *ctx,lw_operation_t mode,
            const uint8_t *input, uint8_t *output);
    int (*cbc_func)(void *ctx,lw_operation_t mode, size_t length,
            uint8_t *iv,const uint8_t *input, uint8_t *output);
    int (*ctr_func)(void *ctx,size_t length,uint8_t *nc_off,
            uint8_t *nonce_counter,uint8_t *stream_block,
            const uint8_t *input, uint8_t *output);
    int (*setkey_enc_func)(void *ctx,const uint8_t *key,
            unsigned int key_bitlen);
    int (*setkey_dec_func)(void *ctx,const uint8_t *key,
            unsigned int key_bitlen);
    /** Allocate a new context */
    void * (*ctx_alloc_func)(uint8_t block_size);

    /** Free the given context */
    void (*ctx_free_func)(void *ctx);
}lw_cipher_base_t;

typedef struct {
    lw_cipher_type_t type;
    const lw_cipher_info_t *info;
}lw_cipher_definition_t;

extern const lw_cipher_definition_t lw_cipher_definitions[];

extern const lw_cipher_base_t *lw_cipher_base_lookup_table[];

#endif //LWCIPHER_LW_CIPHER_WRAPPER_H
