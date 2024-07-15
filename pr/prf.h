#ifndef _PRF
#define _PRF

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

static inline EVP_CIPHER_CTX *prf_key_gen(uint8_t *key)
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        printf("an error ocurred when creating EVP_CIPHER_CTX\n");

    // Note: we use ECB-mode (instead of CTR) as we want to manage each block separately.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        printf("errors ocurred in generating new AES key\n");

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    return ctx;
}

static inline void destroy_ctx_key(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

static inline void prf_eval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs)
{
    int len = 0;
    if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16))
        printf("errors ocurred in PRF evaluation\n");

    // XOR with input to prevent inversion using Davies–Meyer construction
    outputs[0] ^= input[0];
}

static inline void prf_batch_eval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs, int num_blocks)
{
    static int len = 0; // make static to avoid reallocating
    EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks);

    // XOR with input to prevent inversion using Davies–Meyer construction
    for (size_t i = 0; i < num_blocks; i++)
        outputs[i] ^= input[i];

    // DEBUG
    // if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks))
    //     printf("errors ocurred in PRF evaluation\n");
}

static inline void aes_batch_eval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs, int num_blocks)
{
    static int len = 0; // make static to avoid reallocating
    EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks);
}

#endif
