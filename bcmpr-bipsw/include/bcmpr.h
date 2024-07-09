#ifndef _BCMPR
#define _BCMPR

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

struct Params
{
    size_t key_len;
    EVP_CIPHER_CTX *hash_ctx;
    EC_GROUP *curve;
    BIGNUM *order;
    BN_CTX *ctx;
    const EC_POINT *g;
};

struct Key
{
    BIGNUM **key;

    // optional
    BIGNUM *delta;
    EC_POINT **offsets;
};

struct KeyCache
{
    size_t cache_bits;
    BIGNUM **cache;
};

int setup(struct Params *pp, size_t key_len);
int key_gen(struct Params *pp, struct Key *msk);

int sender_eval(
    struct Params *pp,
    struct KeyCache *msk_cache,
    uint128_t *inputs,
    uint128_t *outputs,
    size_t num_ots);

int receiver_eval(
    struct Params *pp,
    struct Key *csk0,
    struct Key *csk1,
    struct KeyCache *csk_cache_0,
    struct KeyCache *csk_cache_1,
    uint8_t *constraint,
    uint128_t *inputs,
    uint128_t *outputs,
    size_t num_ots);

int constrain_key_gen(
    struct Params *pp,
    struct Key *msk,
    struct Key *csk,
    uint8_t *constraint,
    size_t index);

int compute_cache(
    struct Params *pp,
    BIGNUM **key,
    struct KeyCache *key_cache,
    size_t cache_bits);

void free_master_key(struct Params *pp, struct Key *msk);
void free_constrained_key(struct Params *pp, struct Key *csk);
void free_cache(struct Params *pp, struct KeyCache *key_cache);
void free_public_params(struct Params *pp);

static inline size_t get_curve_point_byte_size(struct Params *pp)
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
