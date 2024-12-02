/*
 * @file xtea.h
 *
 * @brief   This file includes the API declaration for the XTEA block cipher.
 *
 *          In cryptography, XTEA (eXtended TEA) is a block cipher designed to
 *          correct weaknesses in TEA. The cipher's designers were David Wheeler
 *          and Roger Needham of the Cambridge Computer Laboratory, and the
 *          algorithm was presented in an unpublished technical report in 1997
 *          (Needham and Wheeler, 1997). The cipher has a 64-bit block size and
 *          a 128-bit key size.
 *
 *          The original paper you can find in the following link:
 *          https://www.cl.cam.ac.uk/ftp/users/djw3/xtea.ps
 *
 * */


#ifndef LWCIPHER_XTEA_H
#define LWCIPHER_XTEA_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @struct  lw_xtea_context
 * @brief   Structure for the XTEA context, the key is stored into for WORDS(32 bits) to adjust the algorithm.
 * */
typedef struct lw_xtea_context {
    uint32_t key[4];
} lw_xtea_context;

#define XTEA_ENCRYPT     1
#define XTEA_DECRYPT     0

#define    LW_ERR_ERROR_CORRUPTION_DETECTED   (-0x000E)    /**< Corrupted data detected. */
#define    LW_ERR_XTEA_BAD_INPUT_DATA        (-0x0010)    /**< Bad input parameters to function. */
#define    LW_ERR_XTEA_INVALID_INPUT_LENGTH  (-0x0011)    /**< Invalid data input length. */

/*
 * @brief   This function initializes the XTEA context in order to use the XTEA algorithm.
 *          In the implementation, it is memset(ctx, 0, sizeof(lw_xtea_context)).
 * @param   ctx: pointer to a lw_xtea_context structure.
 * @retval  None
 * */
void lw_xtea_init(lw_xtea_context *ctx);

/*
 * @brief   This function free the XTEA context in order to use the XTEA algorithm.
 *          In the implementation, it is memset(ctx, 0, sizeof(lw_xtea_context)).
 * @param   ctx: pointer to a lw_xtea_context structure.
 * @retval  None
 * */
void lw_xtea_free(lw_xtea_context *ctx);

/*
 * @brief   This function set the key for the XTEA algorithm, using memcpy.
 * @param   ctx: pointer to a lw_xtea_context structure.
 * @param   key: pointer to the key.
 * @param   key_bitlen: bit length of the key.
 * @retval  0 if the key is set correctly, -1 otherwise.
 * */
int lw_xtea_setkey(lw_xtea_context *ctx, const uint8_t key[16], unsigned int key_bitlen);

/*
 * @brief   This function encrypts or decrypts a block of 8 bytes with XTEA algorithm.
 * @param   ctx: pointer to a lw_xtea_context structure.
 * @param   mode: XTEA_ENCRYPT or XTEA_DECRYPT.
 * @param   input: pointer to the input data.
 * @param   output: pointer to the output data.
 * @retval  0 if the block is encrypted or decrypted correctly, -1 otherwise.
 * */
int lw_xtea_crypt_ecb(lw_xtea_context *ctx, int mode, const uint8_t input[8],
                      uint8_t output[8]);

/*
 * @brief   This function encrypts or decrypts a block of 8 bytes with XTEA algorithm in CBC mode.
 * @param   ctx: pointer to a lw_xtea_context structure.
 * @param   mode: XTEA_ENCRYPT or XTEA_DECRYPT.
 * @param   length: length of the input data.
 * @param   iv: initialization vector.
 * @param   input: pointer to the input data.
 * @param   output: pointer to the output data.
 * @retval  0 if the block is encrypted or decrypted correctly, -1 otherwise.
 */
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
