#ifndef _BIPSW
#define _BIPSW

#include <stdint.h>
#include <openssl/evp.h>
#include "polymur.h"

#ifdef AVX
#include <immintrin.h>
#endif

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

typedef struct
{
    uint128_t *key_2;
    uint128_t *key_3;

    // optional (only for MSK)
    uint128_t correction_2;
    uint128_t *corrections_3;
    uint8_t *delta;
} Key;

typedef struct
{
    uint128_t *cache_2;
    uint128_t *cache_3;
#ifdef AVX
    __m512i *cache_2_avx;
    __m512i *cache_3_avx;
#endif

} KeyCache;

typedef struct
{
    size_t key_len;
    EVP_CIPHER_CTX *hash_ctx;
    EVP_CIPHER_CTX *prg_ctx;
} PublicParams;

void pp_gen(
    PublicParams *pp,
    const size_t key_len);

void pp_free(PublicParams *pp);

void key_gen(
    const PublicParams *pp,
    Key *msk);

void constrain_key_gen(
    const PublicParams *pp,
    const Key *msk,
    Key *csk,
    const uint8_t *constraint);

void sender_eval(
    const PublicParams *pp,
    const Key *msk,
    const KeyCache *csk_cache,
    const uint16_t *inputs,
    uint8_t *outputs,
    const size_t num_ots);

void receiver_eval(
    const PublicParams *pp,
    const Key *csk,
    const KeyCache *csk_cache,
    const uint16_t *inputs,
    uint8_t *outputs,
    const size_t num_ots);

void compute_key_caches(
    const PublicParams *pp,
    const Key *key,
    KeyCache *key_cache,
    const size_t mem_size);

void compute_correction_terms(
    Key *msk,
    const uint8_t *delta);

#endif
