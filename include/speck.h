#ifndef LWCIPHER_SPECK_H
#define LWCIPHER_SPECK_H
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lw_speck_context
{
    uint8_t key[32]; // max key size, it can be 8, 9, 12, 16, 18, 24, 32
    uint16_t key_bitlen; // in bits
    uint8_t block_size; // in bytes
    uint8_t round_limit;
    uint8_t key_schedule[576];
    uint8_t alpha;
    uint8_t beta;

    void (*encryptPtr)(const uint8_t, const uint8_t *, const uint8_t *, uint8_t *);

    void (*decryptPtr)(const uint8_t, const uint8_t *, const uint8_t *, uint8_t *);
} lw_speck_context;

typedef struct _bitword24_t{
    uint32_t data: 24;
} bitword24_t;

typedef struct _bytes3_t{
    uint8_t data[3];
} bytes3_t;

typedef struct _bitword48_t{
    uint64_t data: 48;
} bitword48_t;

typedef struct _bytes6_t{
    uint8_t data[6];
} bytes6_t;

#define SPECK_ENCRYPT     1
#define SPECK_DECRYPT     0
#define    LW_ERR_ERROR_CORRUPTION_DETECTED   (-0x000E)    /**< Corrupted data detected. */
#define    LW_ERR_SPECK_INVALID_CONFIG  (-0x0040)    /**< Invalid data input length. */
#define    LW_ERR_SPECK_BAD_INPUT_DATA        (-0x0041)    /**< Bad input parameters to function. */
#define    LW_ERR_SPECK_INVALID_INPUT_LENGTH  (-0x0042)    /**< Invalid data input length. */

void lw_speck_init(lw_speck_context *ctx, uint8_t block_size);

void lw_speck_free(lw_speck_context *ctx);

int lw_speck_setkey(lw_speck_context *ctx, const uint8_t *key, uint16_t key_bitlen);

void Speck_Encrypt_32(uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Speck_Encrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Speck_Encrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Speck_Encrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext);

void Speck_Encrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *plaintext,
                       uint8_t *ciphertext);

void Speck_Decrypt_32(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Speck_Decrypt_48(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Speck_Decrypt_64(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Speck_Decrypt_96(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext);

void Speck_Decrypt_128(const uint8_t round_limit, const uint8_t *key_schedule, const uint8_t *ciphertext,
                       uint8_t *plaintext);

int lw_speck_crypt_ecb(lw_speck_context *ctx, int mode, const uint8_t input[8],
                       uint8_t output[8]);

int lw_speck_crypt_cbc(lw_speck_context *ctx, int mode, size_t length,
                       uint8_t iv[8], const uint8_t *input, uint8_t *output);

int lw_speck_crypt_ctr(lw_speck_context *ctx, size_t length, uint8_t *nc_off,
                       uint8_t nonce_counter[8], uint8_t stream_block[8],
                       const uint8_t *input, uint8_t *output);

int lw_speck_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif //LWCIPHER_SPECK_H
