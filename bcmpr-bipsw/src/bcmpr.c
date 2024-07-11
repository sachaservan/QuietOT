#include "prf.h"
#include "bcmpr.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <math.h>
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

    uint128_t hash_key;
    RAND_bytes((uint8_t *)&hash_key, sizeof(uint128_t));
    EVP_CIPHER_CTX *hash_ctx = prf_key_gen((uint8_t *)&hash_key);

    pp->hash_ctx = hash_ctx;

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
    msk->offsets = malloc(sizeof(void *) * pp->key_len);

    // generate a new key for Naor-Reingold
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

    BN_set_word(msk->delta, 2); // TODO: remove

    // sample Delta and offsets
    BIGNUM *delta_pow = BN_new();
    BN_set_word(delta_pow, 1);

    BIGNUM *delta_pow_inv = BN_new();
    BN_set_word(delta_pow_inv, 1);

    // compute all the necessary offsets that are later used in the
    // constrained evaluation algorithm
    for (size_t i = 0; i < pp->key_len; i++)
    {
        msk->offsets[i] = EC_POINT_new(pp->curve);

        if (!EC_POINT_mul(
                pp->curve,
                msk->offsets[i],
                delta_pow_inv,
                NULL,
                NULL,
                pp->ctx))
            goto err;

        BN_mod_mul(delta_pow, delta_pow, msk->delta, pp->order, pp->ctx);
        BN_mod_inverse(delta_pow_inv, delta_pow, pp->order, pp->ctx);
    }

    BN_free(delta_pow);
    BN_free(delta_pow_inv);

    return 1;

err:
    free_master_key(pp, msk);
    if (delta_pow)
        BN_free(delta_pow);
    if (delta_pow_inv)
        BN_free(delta_pow_inv);
    return 0;
}

int constrain_key_gen(
    Params *pp,
    Key *msk,
    Key *csk,
    uint8_t *constraint,
    size_t index)
{
    csk->key = malloc(sizeof(void *) * pp->key_len);

    for (size_t i = 0; i < pp->key_len; i++)
    {
        csk->key[i] = BN_new();
        if (!BN_copy(csk->key[i], msk->key[i]))
            goto err;

        if (!constraint[i])
            continue;

        BN_mod_mul(csk->key[i], msk->key[i], msk->delta, pp->order, pp->ctx);
    }

    if (index == 0)
    {
        csk->offsets = malloc(sizeof(void *) * pp->key_len);
        for (size_t i = 0; i < pp->key_len; i++)
        {
            csk->offsets[i] = EC_POINT_new(pp->curve);
            if (is_in_constrained_set(i, pp->key_len))
                EC_POINT_copy(csk->offsets[i], msk->offsets[i]);
        }
    }
    else
    {
        csk->offsets = malloc(sizeof(void *) * pp->key_len);
        for (size_t i = 0; i < pp->key_len; i++)
        {
            csk->offsets[i] = EC_POINT_new(pp->curve);
            if (!is_in_constrained_set(i, pp->key_len))
                EC_POINT_copy(csk->offsets[i], msk->offsets[i]);
        }
    }

    return 1;

err:
    return 0;
}

int compute_cache(
    Params *pp,
    BIGNUM **key,
    KeyCache *key_cache,
    size_t cache_bits)
{

    const size_t cache_block_size = (1UL << cache_bits);

    key_cache->cache_bits = cache_bits;
    key_cache->cache = malloc(
        sizeof(void *) * (pp->key_len / cache_bits) * cache_block_size);

    BIGNUM *result;

    // go through each block of cache_bits key chunks
    for (size_t b = 0; b < pp->key_len / cache_bits; b++)
    {
        // iterate through all possible 2^cache_bits inputs
        for (size_t x = 0; x < cache_block_size; x++)
        {
            key_cache->cache[b * cache_block_size + x] = BN_new();
            result = key_cache->cache[b * cache_block_size + x];
            if (!result)
                goto err;

            // initialize to one
            if (!BN_set_word(result, 1))
                goto err;

            // compute result for this input and key chunk
            for (size_t i = 0; i < cache_bits; i++)
            {
                if (!((x >> i) & 1)) // if i-th input bit is NOT set
                    continue;

                // compute result *= msk[i]
                size_t key_idx = b * cache_bits + i;
                if (!BN_mod_mul(result, result, key[key_idx], pp->order, pp->ctx))
                    goto err;
            }
        }
    }

    return 1;

err:
    free(key_cache->cache);
    free(key_cache);

    return 0;
}

int sender_eval(
    Params *pp,
    KeyCache *msk_cache,
    uint128_t *inputs,
    uint128_t *outputs,
    size_t num_ots)
{

    BIGNUM *result = BN_new();
    if (!result)
        goto err;

    EC_POINT *out = EC_POINT_new(pp->curve);
    if (!out)
        goto err;

    // get byte size of curve point
    size_t point_len = get_curve_point_byte_size(pp);
    size_t point_len_blocks = (point_len / 16); // how many fit in uint128_t
    uint8_t *point_bytes = (uint8_t *)malloc(point_len);

    uint128_t *prf_inputs = malloc(sizeof(uint128_t) * num_ots * point_len_blocks);

    size_t input_step = ceil((pp->key_len) / 128);

    const size_t cache_block_size = (1UL << CACHE_BITS);

    size_t cache_offset;
    size_t chunk_mask = (cache_block_size - 1);
    uint128_t *current_input;
    size_t i, input_chunk;
    for (size_t n = 0; n < num_ots; n++)
    {
        current_input = &inputs[input_step * n];

        // initialize to one
        if (!BN_set_word(result, 1))
            goto err;

        input_chunk = 0;
        cache_offset = 0;
        size_t x;
        for (size_t i = 0; i < pp->key_len; i += CACHE_BITS)
        {
            x = (current_input[0] >> input_chunk) & chunk_mask;

            // compute result *= msk[i]
            BN_mod_mul(
                result,
                result,
                msk_cache->cache[cache_offset + x],
                pp->order,
                pp->ctx);

            input_chunk += CACHE_BITS;
            if (input_chunk % 128 == 0)
            {
                input_chunk = 0;
                current_input++;
            }

            cache_offset += cache_block_size;
        }

        EC_POINT_mul(
            pp->curve,
            out,
            result,
            NULL,
            NULL,
            pp->ctx);

        EC_POINT_point2oct(
            pp->curve,
            out,
            POINT_CONVERSION_COMPRESSED,
            point_bytes,
            point_len,
            pp->ctx);

        // ignore the y coordinate stored in [0]
        memcpy(&prf_inputs[point_len_blocks * n], &point_bytes[1], point_len - 1);
    }

    prf_batch_eval(
        pp->hash_ctx,
        &prf_inputs[0],
        &outputs[0],
        num_ots * point_len_blocks);

    free(point_bytes);
    free(prf_inputs);
    BN_free(result);
    EC_POINT_free(out);

    return 1;

err:
    ERR_print_errors_fp(stderr);

    if (result)
        BN_free(result);
    if (out)
        EC_POINT_free(out);

    free(prf_inputs);
    free(point_bytes);

    return 0;
}

int receiver_eval(
    Params *pp,
    Key *csk0,
    Key *csk1,
    KeyCache *csk_cache_0,
    KeyCache *csk_cache_1,
    uint8_t *constraint,
    uint128_t *inputs,
    uint128_t *outputs,
    size_t num_ots)
{

    const size_t cache_block_size = (1UL << CACHE_BITS);

    BIGNUM *result = BN_new();
    if (!result)
        goto err;

    BIGNUM *result_msk = BN_new();
    if (!result)
        goto err;

    EC_POINT *out = EC_POINT_new(pp->curve);
    if (!out)
        goto err;

    // get byte size of curve point
    size_t point_len = get_curve_point_byte_size(pp);
    size_t point_len_blocks = (point_len / 16); // how many fit in uint128_t
    uint8_t *point_bytes = (uint8_t *)malloc(point_len);

    uint128_t *prf_inputs = malloc(sizeof(uint128_t) * num_ots * point_len_blocks);

    Key *csk;
    KeyCache *csk_cache;

    size_t input_step = ceil((pp->key_len) / 128);

    size_t cache_offset;
    size_t chunk_mask = ((1 << CACHE_BITS) - 1);
    size_t i, ip, input_chunk;
    for (size_t n = 0; n < num_ots; n++)
    {
        uint128_t *current_input = &inputs[input_step * n];

        //*********************************************
        // Step 1: figure out which of the two keys are constrained based on
        // the inner product
        //*********************************************

        ip = 0;
        input_chunk = 0;
        for (size_t i = 0; i < pp->key_len; i += CACHE_BITS)
        {
            size_t x = (current_input[0] >> input_chunk) & chunk_mask;

            for (size_t j = 0; j < CACHE_BITS; j++)
                ip += ((x >> j) & 1) * constraint[i + j];

            input_chunk += CACHE_BITS;
            if (input_chunk % 128 == 0)
            {
                input_chunk = 0;
                current_input++;
            }
        }

        if (is_in_constrained_set(ip, pp->key_len))
        {
            csk = csk0;
            csk_cache = csk_cache_0;
        }
        else
        {
            csk = csk1;
            csk_cache = csk_cache_1;
        }

        //*********************************************
        // Step 2: Compute the non-constrained CPRF
        //*********************************************

        // initialize to one
        if (!BN_set_word(result, 1))
            goto err;

        if (!BN_set_word(result_msk, 1))
            goto err;

        // reset the current input
        current_input = &inputs[input_step * n];

        cache_offset = 0;
        input_chunk = 0;
        for (size_t i = 0; i < pp->key_len; i += CACHE_BITS)
        {
            size_t x = (current_input[0] >> input_chunk) & chunk_mask;

            // compute result *= csk[i]
            BN_mod_mul(
                result,
                result,
                csk_cache->cache[cache_offset + x],
                pp->order, pp->ctx);

            input_chunk += CACHE_BITS;
            if (input_chunk % 128 == 0)
            {
                input_chunk = 0;
                current_input++;
            }

            cache_offset += cache_block_size;
        }

        EC_POINT_mul(
            pp->curve,
            out,
            NULL,
            csk->offsets[ip],
            result,
            pp->ctx);

        EC_POINT_point2oct(
            pp->curve,
            out,
            POINT_CONVERSION_COMPRESSED,
            point_bytes,
            point_len,
            pp->ctx);

        // ignore the y coordinate stored in [0]
        memcpy(&prf_inputs[point_len_blocks * n], &point_bytes[1], point_len - 1);
    }

    prf_batch_eval(
        pp->hash_ctx, &prf_inputs[0], &outputs[0], num_ots * point_len_blocks);

    free(point_bytes);
    free(prf_inputs);
    BN_free(result);
    EC_POINT_free(out);

    return 1;

err:
    ERR_print_errors_fp(stderr);

    if (result)
        BN_free(result);
    if (out)
        EC_POINT_free(out);

    free(prf_inputs);
    free(point_bytes);

    return 0;
}

void free_master_key(Params *pp, Key *msk)
{
    for (size_t i = 0; i < pp->key_len; i++)
    {
        if (msk->key[i])
            BN_free(msk->key[i]);
        if (msk->offsets[i])
            EC_POINT_free(msk->offsets[i]);
    }

    if (msk->delta)
        BN_free(msk->delta);

    free(msk->offsets);
    free(msk->key);
    free(msk);
}

void free_constrained_key(Params *pp, Key *csk)
{
    for (size_t i = 0; i < pp->key_len; i++)
    {
        if (csk->key[i])
            BN_free(csk->key[i]);
    }

    free(csk->offsets);
    free(csk->key);
    free(csk);
}

void free_cache(Params *pp, KeyCache *key_cache)
{
    size_t cache_size = (pp->key_len / key_cache->cache_bits) * (1 << key_cache->cache_bits);
    for (size_t i = 0; i < cache_size; i++)
    {
        if (key_cache->cache[i])
            BN_free(key_cache->cache[i]);
    }
    free(key_cache->cache);
    free(key_cache);
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
