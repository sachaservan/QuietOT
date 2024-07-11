#ifndef _BCMPR
#define _BCMPR

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

typedef struct
{
    size_t key_len;
    EVP_CIPHER_CTX *hash_ctx;
    EC_GROUP *curve;
    BIGNUM *order;
    BN_CTX *ctx;
    const EC_POINT *g;
} Params;

typedef struct
{
    BIGNUM **key;

    // optional
    BIGNUM *delta;
    EC_POINT **offsets;
} Key;

typedef struct
{
    size_t cache_bits;
    BIGNUM **cache;
} KeyCache;

int setup(Params *pp, size_t key_len);
int key_gen(Params *pp, Key *msk);

int sender_eval(
    Params *pp,
    KeyCache *msk_cache,
    uint128_t *inputs,
    uint128_t *outputs,
    size_t num_ots);

int receiver_eval(
    Params *pp,
    Key *csk0,
    Key *csk1,
    KeyCache *csk_cache_0,
    KeyCache *csk_cache_1,
    uint8_t *constraint,
    uint128_t *inputs,
    uint128_t *outputs,
    size_t num_ots);

int constrain_key_gen(
    Params *pp,
    Key *msk,
    Key *csk,
    uint8_t *constraint,
    size_t index);

int compute_cache(
    Params *pp,
    BIGNUM **key,
    KeyCache *key_cache,
    size_t cache_bits);

void free_master_key(Params *pp, Key *msk);
void free_constrained_key(Params *pp, Key *csk);
void free_cache(Params *pp, KeyCache *key_cache);
void free_public_params(Params *pp);

static inline size_t get_curve_point_byte_size(Params *pp)
{
    // get byte size of curve point
    size_t point_len = EC_POINT_point2oct(
        pp->curve,
        EC_GROUP_get0_generator(pp->curve),
        POINT_CONVERSION_COMPRESSED,
        NULL, 0, pp->ctx);

    return point_len;
}

static inline int is_in_constrained_set(int i, int n)
{
    // https://eprint.iacr.org/2024/178.pdf (page 8)
    // S = {i ≤ n : ∃k ≤ n/6, j ∈ {0, 1, 2}, i = 6k + j}
    int k = i / 6;
    int j = i % 6;
    return (k <= n / 6) && (j <= 2);
}

#endif
