#ifndef LWCIPHER_SIMON_H
#define LWCIPHER_SIMON_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lw_simon_context
{
    uint8_t key[32]; // max key size, it can be 8, 9, 12, 16, 18, 24, 32
    uint16_t key_bitlen; // in bits
    uint8_t block_size; // in bytes
    uint8_t round_limit;
    uint8_t key_schedule[576];
    uint8_t z_seq;

    void (*encryptPtr)(const uint8_t, const uint8_t *, const uint8_t *, uint8_t *);

    void (*decryptPtr)(const uint8_t, const uint8_t *, const uint8_t *, uint8_t *);
} lw_simon_context;

typedef struct _bword_24
{
    uint32_t data: 24;
} bword_24;

typedef struct _bword_48
{
    uint64_t data: 48;
} bword_48;

#define SIMON_ENCRYPT     1
#define SIMON_DECRYPT     0

#define    LW_ERR_ERROR_CORRUPTION_DETECTED   (-0x000E)    /**< Corrupted data detected. */
#define    LW_ERR_SIMON_INVALID_CONFIG  (-0x0030)    /**< Invalid data input length. */
#define    LW_ERR_SIMON_BAD_INPUT_DATA        (-0x0031)    /**< Bad input parameters to function. */
#define    LW_ERR_SIMON_INVALID_INPUT_LENGTH  (-0x0032)    /**< Invalid data input length. */

void lw_simon_init(lw_simon_context *ctx, uint8_t block_size);

void lw_simon_free(lw_simon_context *ctx);

int lw_simon_setkey(lw_simon_context *ctx, const uint8_t *key, uint16_t key_bitlen);

void Simon_Encrypt_32(uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Simon_Encrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Simon_Encrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Simon_Encrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Simon_Encrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                       uint8_t *ciphertext);

void Simon_Decrypt_32(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Simon_Decrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Simon_Decrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Simon_Decrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Simon_Decrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                       uint8_t *plaintext);

int lw_simon_crypt_ecb(lw_simon_context *ctx, int mode, const uint8_t input[8],
                       uint8_t output[8]);

int lw_simon_crypt_cbc(lw_simon_context *ctx, int mode, size_t length,
                       uint8_t iv[8], const uint8_t *input, uint8_t *output);

int lw_simon_crypt_ctr(lw_simon_context *ctx, size_t length, uint8_t *nc_off,
                       uint8_t nonce_counter[8], uint8_t stream_block[8],
                       const uint8_t *input, uint8_t *output);

int lw_simon_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif //LWCIPHER_SIMON_H
