#ifndef LWCIPHER_XTEA_H
#define LWCIPHER_XTEA_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lw_xtea_context
{
    uint32_t key[4];
} lw_xtea_context;

#define XTEA_ENCRYPT     1
#define XTEA_DECRYPT     0

#define    LW_ERR_ERROR_CORRUPTION_DETECTED   (-0x000E)    /**< Corrupted data detected. */
#define    LW_ERR_XTEA_BAD_INPUT_DATA        (-0x0010)    /**< Bad input parameters to function. */
#define    LW_ERR_XTEA_INVALID_INPUT_LENGTH  (-0x0011)    /**< Invalid data input length. */
void lw_xtea_init(lw_xtea_context *ctx);

void lw_xtea_free(lw_xtea_context *ctx);

int lw_xtea_setkey(lw_xtea_context *ctx, const uint8_t key[16], unsigned int key_bitlen);

int lw_xtea_crypt_ecb(lw_xtea_context *ctx, int mode, const uint8_t input[8],
                      uint8_t output[8]);

int lw_xtea_crypt_cbc(lw_xtea_context *ctx, int mode, size_t length,
                      uint8_t iv[8], const uint8_t *input, uint8_t *output);

int lw_xtea_crypt_ctr(lw_xtea_context *ctx, size_t length, uint8_t *nc_off,
                      uint8_t nonce_counter[8], uint8_t stream_block[8],
                      const uint8_t *input, uint8_t *output);

int lw_xtea_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif //LWCIPHER_XTEA_H
