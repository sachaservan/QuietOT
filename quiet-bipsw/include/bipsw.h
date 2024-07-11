#ifndef _BIPSW
#define _BIPSW

#include <stdint.h>
#include <openssl/evp.h>
#include "polymur.h"

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

struct Key
{
    uint128_t *key_2;
    uint128_t *key_3;

    // optional (only for MSK)
    uint128_t correction_2;
    uint128_t *corrections_3;
    uint8_t *delta;
};

struct KeyCache
{
    uint128_t *cache_2;
    uint128_t *cache_3;
};

struct PublicParams
{
    size_t key_len;
    EVP_CIPHER_CTX *hash_ctx;
    EVP_CIPHER_CTX *prg_ctx;
    PolymurHashParams polymur_params0;
    PolymurHashParams polymur_params1;
};

void pp_gen(
    struct PublicParams *pp,
    size_t key_len);

void pp_free(struct PublicParams *pp);

void key_gen(
    struct PublicParams *pp,
    struct Key *msk);

void constrain_key_gen(
    struct PublicParams *pp,
    struct Key *msk,
    struct Key *csk,
    uint8_t *constraint);

void sender_eval(
    struct PublicParams *pp,
    struct Key *msk,
    struct KeyCache *csk_cache,
    const uint16_t *inputs,
    uint128_t *outputs,
    const size_t num_ots);

void receiver_eval(
    struct PublicParams *pp,
    struct Key *csk,
    struct KeyCache *csk_cache,
    const uint16_t *inputs,
    uint128_t *outputs,
    const size_t num_ots);

void compute_key_caches(
    struct PublicParams *pp,
    struct Key *key,
    struct KeyCache *key_cache,
    size_t mem_size);

void compute_correction_terms(
    struct Key *msk,
    uint8_t *delta);

#endif
