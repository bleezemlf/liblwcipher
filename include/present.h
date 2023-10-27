#ifndef LWCIPHER_PRESENT_H
#define LWCIPHER_PRESENT_H
#include <stdint.h>
/*
 * block size: 64 bits
 * key size: 80 bits or 128 bits
 * round number: 31 for 80 bits key, 32 for 128 bits key
 * round key size : 64 bits
 * */
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct lw_present_context{
    uint8_t key[16];
    uint8_t key_bitlen;
    uint8_t round_key[32][8];
}lw_present_context;

#define PRESENT_ENCRYPT     1
#define PRESENT_DECRYPT     0

#define    LW_ERR_ERROR_CORRUPTION_DETECTED   (-0x000E)    /**< Corrupted data detected. */
#define    LW_ERR_PRESENT_INVALID_CONFIG  (-0x0050)    /**< Invalid data input length. */
#define    LW_ERR_PRESENT_BAD_INPUT_DATA        (-0x0051)    /**< Bad input parameters to function. */
#define    LW_ERR_PRESENT_INVALID_INPUT_LENGTH  (-0x0052)    /**< Invalid data input length. */

void lw_present_init(lw_present_context *ctx);

void lw_present_free(lw_present_context *ctx);

int lw_present_setkey(lw_present_context *ctx, const uint8_t *key, uint16_t key_bitlen);

int lw_present_crypt_ecb(lw_present_context *ctx, const uint8_t mode, const uint8_t *input, uint8_t *output);

int lw_present_crypt_cbc(lw_present_context *ctx, const uint8_t mode, size_t length, uint8_t iv[8],
                         const uint8_t *input, uint8_t *output);

int lw_present_crypt_ctr(lw_present_context *ctx, size_t length, uint8_t *nc_off, uint8_t nonce_counter[8],
                         uint8_t stream_block[8], const uint8_t *input, uint8_t *output);

int lw_present_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif //LWCIPHER_PRESENT_H
