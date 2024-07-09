#ifndef _PRG
#define _PRG

#include <stdint.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

static inline EVP_CIPHER_CTX *PRGkey_gen(uint8_t *key)
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        printf("an error ocurred when creating EVP_CIPHER_CTX\n");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, NULL))
        printf("errors ocurred in generating new AES key\n");

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    return ctx;
}

static inline void prg_eval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs, int num_blocks)
{
    static int len = 0; // make static to avoid reallocating
    EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks);

    // DEBUG
    // if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks))
    //     printf("errors ocurred in PRF evaluation\n");
}

#endif
