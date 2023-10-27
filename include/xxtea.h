#ifndef LWCIPHER_XXTEA_H
#define LWCIPHER_XXTEA_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lw_xxtea_context
{
    uint32_t key[4];
} lw_xxtea_context;

#define XXTEA_ENCRYPT     1
#define XXTEA_DECRYPT     0

#define    LW_ERR_ERROR_CORRUPTION_DETECTED   (-0x000E)    /**< Corrupted data detected. */
#define    LW_ERR_XXTEA_BAD_INPUT_DATA        (-0x0020)    /**< Bad input parameters to function. */
#define    LW_ERR_XXTEA_INVALID_INPUT_LENGTH  (-0x0021)    /**< Invalid data input length. */
void lw_xxtea_init(lw_xxtea_context *ctx);

void lw_xxtea_free(lw_xxtea_context *ctx);

int lw_xxtea_setkey(lw_xxtea_context *ctx, const uint8_t key[16], unsigned int key_bitlen);

int lw_xxtea_crypt_ecb(lw_xxtea_context *ctx, int mode, const uint8_t input[8],
                       uint8_t output[8]);

int lw_xxtea_crypt_cbc(lw_xxtea_context *ctx, int mode, size_t length,
                       uint8_t iv[8], const uint8_t *input, uint8_t *output);

int lw_xxtea_crypt_ctr(lw_xxtea_context *ctx, size_t length, uint8_t *nc_off,
                       uint8_t nonce_counter[8], uint8_t stream_block[8],
                       const uint8_t *input, uint8_t *output);

int lw_xxtea_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif //LWCIPHER_XXTEA_H
