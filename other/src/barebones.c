
#include "other.h"
#include "params.h"

int setup(Params *pp, size_t key_len)
{
    pp->key_len = key_len;
    pp->curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!pp->curve)
        goto err;

    pp->ctx = BN_CTX_new();
    if (!pp->ctx)
        goto err;

    pp->order = BN_new();
    if (!pp->order)
        goto err;

    EC_GROUP_get_order(pp->curve, pp->order, pp->ctx);

    // g is not NULL as it's managed by the curve
    pp->g = EC_GROUP_get0_generator(pp->curve);

    return 1;

err:
    if (pp)
        free_public_params(pp);
    return 0;
}

int key_gen(Params *pp, Key *msk)
{
    msk->key = malloc(sizeof(void *) * pp->key_len);
    msk->delta = BN_new();

    for (size_t i = 0; i < pp->key_len; i++)
    {
        msk->key[i] = BN_new();
        if (!msk->key[i])
            goto err;

        if (!BN_rand_range(msk->key[i], pp->order)) // k_i
            goto err;
    }

    if (!BN_rand_range(msk->delta, pp->order))
        goto err;

    // sample Delta
    BIGNUM *delta_pow = BN_new();
    if (!BN_copy(delta_pow, msk->delta))
        goto err;

    return 1;

err:
    free_master_key(pp, msk);
    return 0;
}

void free_master_key(Params *pp, Key *msk)
{
    for (size_t i = 0; i < pp->key_len; i++)
    {
        if (msk->key[i])
            BN_free(msk->key[i]);
    }

    if (msk->delta)
        BN_free(msk->delta);

    free(msk->key);
    free(msk);
}

void free_public_params(Params *pp)
{
    if (pp->curve)
        EC_GROUP_free(pp->curve);
    if (pp->ctx)
        BN_CTX_free(pp->ctx);
    if (pp->order)
        BN_free(pp->order);

    free(pp);
}
