#include "prf.h"
#include "prg.h"
#include "gar.h"
#include "utils.h"
#include "params.h"

#include <string.h>
#include <openssl/rand.h>

void pp_gen(PublicParams *pp)
{
    // Generate PRG key (for generating random inputs)
    uint128_t prg_key;
    RAND_bytes((uint8_t *)&prg_key, sizeof(uint128_t));
    EVP_CIPHER_CTX *prg_ctx = PRGkey_gen((uint8_t *)&prg_key);

    // Generate hash key (for random oracle)
    uint128_t hash_key;
    RAND_bytes((uint8_t *)&hash_key, sizeof(uint128_t));
    EVP_CIPHER_CTX *hash_ctx = prf_key_gen((uint8_t *)&hash_key);

    pp->hash_ctx = hash_ctx;
    pp->prg_ctx = prg_ctx;

    PolymurHashParams p0;
    PolymurHashParams p1;
    polymur_init_params_from_seed(&p0, POLYMUR_SEED0);
    polymur_init_params_from_seed(&p1, POLYMUR_SEED1);
    pp->polymur_params0 = p0;
    pp->polymur_params1 = p1;
}

void pp_free(PublicParams *pp)
{
    destroy_ctx_key(pp->hash_ctx);
    destroy_ctx_key(pp->prg_ctx);
    free(pp);
}

void key_gen(PublicParams *pp, Key *msk)
{
    msk->key_xor = malloc(sizeof(uint128_t) * KEY_LEN);
    msk->key_maj = malloc(sizeof(uint8_t) * KEY_LEN * RING_DIM);

    // pack all 128 ring elements of Z_2^128 into one uint128
    RAND_bytes((uint8_t *)msk->key_xor, sizeof(uint128_t) * KEY_LEN);

    // store each element of Z_(MAJ_LEN+1) as a uint8_t
    RAND_bytes((uint8_t *)msk->key_maj, sizeof(uint8_t) * KEY_LEN * RING_DIM);
    for (int i = 0; i < KEY_LEN * RING_DIM; i++)
        msk->key_maj[i] &= MAJ_LEN; // equivalent to %= (MAJ_LEN+1)

    // Sample the random Delta for the constraint key
    RAND_bytes((uint8_t *)&msk->xor_delta, sizeof(uint128_t));

    msk->maj_delta = malloc(sizeof(uint8_t) * RING_DIM);
    RAND_bytes((uint8_t *)msk->maj_delta, sizeof(uint8_t) * RING_DIM);

    msk->maj_corrections = malloc(sizeof(uint8_t) * RING_DIM * NUM_COMBOS);
    compute_correction_terms(msk->maj_delta, &msk->maj_corrections[0]);
}

void constrain_key_gen(
    PublicParams *pp,
    Key *msk,
    Key *csk,
    uint8_t *constraint)
{

    csk->key_xor = malloc(sizeof(uint128_t) * KEY_LEN);
    csk->key_maj = malloc(sizeof(uint8_t) * KEY_LEN * RING_DIM);
    for (size_t i = 0; i < KEY_LEN; i++)
        csk->key_xor[i] = msk->key_xor[i] ^ (msk->xor_delta * constraint[i]);

    for (size_t i = 0; i < KEY_LEN; i++)
    {
        for (size_t j = 0; j < RING_DIM; j++)
        {
            csk->key_maj[RING_DIM * i + j] = msk->key_maj[RING_DIM * i + j];
            csk->key_maj[RING_DIM * i + j] += (msk->maj_delta[j] * constraint[i]);
            csk->key_maj[RING_DIM * i + j] &= MAJ_LEN; // equivalent to %= (MAJ_LEN+1)
        }
    }
}

void compute_correction_terms(
    uint8_t *maj_delta,
    uint8_t *maj_corrections)
{

    for (size_t i = 0; i < NUM_COMBOS; i++)
    {
        for (size_t j = 0; j < RING_DIM; j++)
        {
            uint8_t corr = ((uint8_t)i) * maj_delta[j];
            maj_corrections[RING_DIM * i + j] = (corr & MAJ_LEN);
        }

        // DEBUG
        // printf("maj_corrections[%zu]=: ", i);
        // for (size_t j = 0; j < RING_DIM; j++)
        // printf("%i ", maj_corrections[RING_DIM * i + j]);
        // printf("\n");
    }
}

static inline void common_eval(
    const Key *key,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint128_t *xor_outputs,
    uint8_t *maj_outputs,
    const size_t num_ots)
{
    // pointers to the current input
    const uint16_t *xor_input;
    const uint16_t *maj_input;
    uint8_t *maj_output;

    size_t xor_input_offset = 0;
    size_t maj_input_offset = 0;

    // pointer to the current key block
    const uint8_t *maj_key_block;

    uint128_t xor ;         // xor output
    uint16_t maj[RING_DIM]; // maj output

    uint8_t i, j;
    for (size_t n = 0; n < num_ots; n++)
    {
        xor_input = &xor_inputs[xor_input_offset];
        maj_input = &maj_inputs[maj_input_offset];

        // do the first iteration separately to initialize xor
        xor = key->key_xor[xor_input[0]];
        for (i = 1; i < XOR_LEN; i++)
            xor ^= key->key_xor[xor_input[i]];

        // do the first iteration separately to initialize maj[i]
        maj_key_block = &key->key_maj[maj_input[0] * RING_DIM];
        for (j = 0; j < RING_DIM; j++)
            maj[j] = maj_key_block[j];

        for (i = 1; i < MAJ_LEN; i++)
        {
            maj_key_block = &key->key_maj[maj_input[i] * RING_DIM];

            // TODO[optimization]: explicitly vectorize
            for (j = 0; j < RING_DIM; j++)
                maj[j] += maj_key_block[j];
        }

        xor_outputs[n] = xor;

        maj_output = &maj_outputs[n * RING_DIM];
        for (j = 0; j < RING_DIM; j++)
            maj_output[j] = maj[j] & MAJ_LEN; // equivalent to %= (MAJ_LEN +1)

        xor_input_offset += XOR_LEN;
        maj_input_offset += MAJ_LEN;
    }
}

void sender_eval(
    PublicParams *pp,
    Key *msk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint128_t *outputs,
    const size_t num_ots)
{

    uint128_t *xor_outputs = malloc(sizeof(uint128_t) * num_ots);
    uint8_t *maj_outputs = malloc(sizeof(uint8_t) * num_ots * RING_DIM);
    uint8_t *uhash_in = malloc(sizeof(uint8_t) * RING_DIM);

    common_eval(
        msk,
        xor_inputs,
        maj_inputs,
        xor_outputs,
        maj_outputs,
        num_ots);

    // to_hash structure: [xor0, xor1, maj_0 ... maj_k]
    uint128_t *hash_in_xor = malloc(sizeof(uint128_t) * num_ots * 2);
    uint128_t *hash_out_xor = malloc(sizeof(uint128_t) * num_ots * 2);

    uint128_t *hash_in_maj = malloc(sizeof(uint128_t) * num_ots * (MAJ_LEN + 1));
    uint128_t *hash_out_maj = malloc(sizeof(uint128_t) * num_ots * (MAJ_LEN + 1));

    // compute the values for all xor hash components
    for (size_t n = 0; n < num_ots; n++)
    {
        hash_in_xor[n * 2] = xor_outputs[n];
        hash_in_xor[n * 2 + 1] = xor_outputs[n] ^ msk->xor_delta;
    }

    // variables used in the next loop
    const uint8_t *maj;
    size_t index;
    const uint8_t *correction;
    size_t i, j;

    // compute the values for all maj hash components with a universal hashing
    for (size_t n = 0; n < num_ots; n++)
    {
        // DEBUG
        // if (n == 0)
        // {
        //     printf("maj[sender] ");
        //     for (j = 0; j < MAJ_LEN; j++)
        //         printf("%i ", maj_outputs[n * MAJ_LEN + j]);
        //     printf("\n");
        // }

        maj = &maj_outputs[n * RING_DIM];
        index = n * (MAJ_LEN + 1);
        for (i = 0; i < (MAJ_LEN + 1); i++)
        {
            correction = &msk->maj_corrections[RING_DIM * i];

            for (j = 0; j < RING_DIM; j++)
                uhash_in[j] = ((maj[j] + correction[j]) & MAJ_LEN);

            hash_in_maj[index] = universal_hash(pp, uhash_in, RING_DIM);

            index++;
        }
    }

    prf_batch_eval(pp->hash_ctx, &hash_in_xor[0], &hash_out_xor[0], num_ots * 2);
    prf_batch_eval(pp->hash_ctx, &hash_in_maj[0], &hash_out_maj[0], num_ots * (MAJ_LEN + 1));

    // XOR both outputs together
    for (size_t n = 0; n < num_ots; n++)
    {
        size_t out_index_0 = n * NUM_COMBOS;
        size_t out_index_1 = n * NUM_COMBOS + (MAJ_LEN + 1);

        for (i = 0; i < (MAJ_LEN + 1); i++)
        {
            // the maj part is reused for both the lower and upper half
            outputs[out_index_0 + i] = hash_out_xor[2 * n] ^ hash_out_maj[out_index_0 / 2 + i];
            outputs[out_index_1 + i] = hash_out_xor[2 * n + 1] ^ hash_out_maj[out_index_0 / 2 + i];
        }
    }

    free(hash_in_xor);
    free(hash_out_xor);
    free(hash_in_maj);
    free(hash_out_maj);
    free(xor_outputs);
    free(maj_outputs);
}

void receiver_eval(
    PublicParams *pp,
    Key *csk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint128_t *outputs,
    const size_t num_ots)
{

    uint128_t *xor_outputs = malloc(sizeof(uint128_t) * num_ots);
    uint8_t *maj_outputs = malloc(sizeof(uint8_t) * num_ots * RING_DIM);
    uint8_t *uhash_in = malloc(sizeof(uint8_t) * RING_DIM);

    uint128_t *hash_out_xor = malloc(sizeof(uint128_t) * num_ots);
    uint128_t *hash_in_maj = malloc(sizeof(uint128_t) * num_ots);
    uint128_t *hash_out_maj = malloc(sizeof(uint128_t) * num_ots);

    common_eval(
        csk,
        xor_inputs,
        maj_inputs,
        xor_outputs,
        maj_outputs,
        num_ots);

    uint128_t tmp;
    uint8_t *maj;

    size_t j;
    for (size_t n = 0; n < num_ots; n++)
    {
        uhash_in = &maj_outputs[n * RING_DIM];
        hash_in_maj[n] = universal_hash(pp, uhash_in, RING_DIM);
    }

    prf_batch_eval(pp->hash_ctx, &xor_outputs[0], &hash_out_xor[0], num_ots);
    prf_batch_eval(pp->hash_ctx, &hash_in_maj[0], &hash_out_maj[0], num_ots);

    // XOR both outputs together
    for (size_t n = 0; n < num_ots; n++)
        outputs[n] = hash_out_xor[n] ^ hash_out_maj[n];

    free(xor_outputs);
    free(maj_outputs);
    free(hash_in_maj);
    free(hash_out_maj);
    free(hash_out_xor);
}

void GenerateRandomInputs(
    PublicParams *pp,
    uint16_t *xor_inputs,
    uint16_t *maj_inputs,
    size_t num_ots)
{
    // randomness we will use to generate random indices
    // we sample RAND_BUFFER more bytes in case sampled values are
    // rejected and sample RAND_OFFSET_MAX times more randomness in case the
    // sampled set of indices are not unique and the entire set is rejected
    //
    // TODO[optimization] make this extra randomness sampling more tight
    uint16_t *randomness_xor_out = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (XOR_LEN + RAND_BUFFER));
    uint16_t *randomness_xor_in = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (XOR_LEN + RAND_BUFFER));
    uint16_t *randomness_maj_in = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (MAJ_LEN + RAND_BUFFER));
    uint16_t *randomness_maj_out = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (MAJ_LEN + RAND_BUFFER));

    // initialize to different values between xor and maj
    for (size_t i = 0; i < num_ots * (XOR_LEN + RAND_BUFFER); i++)
        randomness_xor_in[i] = 0;
    for (size_t i = 0; i < num_ots * (MAJ_LEN + RAND_BUFFER); i++)
        randomness_maj_in[i] = 1;

    clock_t t = clock();

    prg_eval(pp->prg_ctx, (uint128_t *)randomness_xor_in, (uint128_t *)randomness_xor_out, RAND_OFFSET_MAX * num_ots * (XOR_LEN + RAND_BUFFER) / 8);
    prg_eval(pp->prg_ctx, (uint128_t *)randomness_maj_in, (uint128_t *)randomness_maj_out, RAND_OFFSET_MAX * num_ots * (MAJ_LEN + RAND_BUFFER) / 8);

    int status = 0;
    // offset in randomness in case of failures
    size_t offset_xor = 0;
    size_t offset_maj = 0;
    for (size_t i = 0; i < num_ots; i++)
    {
        status = 0;
        while (!status)
        {
            status = sample_random_distinct_key_indices(
                &randomness_xor_out[(i + offset_xor) * (XOR_LEN + RAND_BUFFER)],
                &xor_inputs[i * XOR_LEN],
                XOR_LEN);
            offset_xor++;
        }

        status = 0;
        while (!status)
        {
            // TODO[style] fix the indexing and explain the logic
            status = sample_random_distinct_key_indices(
                &randomness_maj_out[(i + offset_maj) * (MAJ_LEN + RAND_BUFFER)],
                &maj_inputs[i * MAJ_LEN],
                MAJ_LEN);
            offset_maj++;
        }
    }

    free(randomness_xor_in);
    free(randomness_maj_in);
    free(randomness_xor_out);
    free(randomness_maj_out);
}
