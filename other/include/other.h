#ifndef _OTHER
#define _OTHER

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdint.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

struct Params
{
    size_t key_len;
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
};

struct KeyCache
{
    size_t cache_bits;
    BIGNUM **cache;
};

int setup(struct Params *pp, size_t key_len);
int key_gen(struct Params *pp, struct Key *msk);

void free_master_key(struct Params *pp, struct Key *msk);
void free_public_params(struct Params *pp);

static inline size_t get_curve_point_byte_size(struct Params *pp)
{
    // get byte size of curve point
    size_t point_len = EC_POINT_point2oct(
        pp->curve,
        EC_GROUP_get0_generator(pp->curve),
        POINT_CONVERSION_COMPRESSED,
        NULL, 0, pp->ctx);
    point_len -= 1; // ignore the y coordinate
    point_len /= sizeof(uint128_t);

    return point_len;
}

#endif
