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

    pp->prg_ctx = prg_ctx;

    // Generate hash key (for random oracle)
    uint128_t hash_key0;
    RAND_bytes((uint8_t *)&hash_key0, sizeof(uint128_t));
    EVP_CIPHER_CTX *hash_ctx0 = prf_key_gen((uint8_t *)&hash_key0);

    // Generate hash key (for random oracle)
    uint128_t hash_key1;
    RAND_bytes((uint8_t *)&hash_key1, sizeof(uint128_t));
    EVP_CIPHER_CTX *hash_ctx1 = prf_key_gen((uint8_t *)&hash_key1);

    // Generate hash key (for random oracle)
    uint128_t hash_key2;
    RAND_bytes((uint8_t *)&hash_key2, sizeof(uint128_t));
    EVP_CIPHER_CTX *hash_ctx2 = prf_key_gen((uint8_t *)&hash_key2);

    pp->hash_ctx0 = hash_ctx0;
    pp->hash_ctx1 = hash_ctx1;
    pp->hash_ctx2 = hash_ctx2;

    PolymurHashParams p0;
    PolymurHashParams p1;
    polymur_init_params_from_seed(&p0, POLYMUR_SEED0);
    polymur_init_params_from_seed(&p1, POLYMUR_SEED1);
    pp->polymur_params0 = p0;
    pp->polymur_params1 = p1;
}

void pp_free(PublicParams *pp)
{
    destroy_ctx_key(pp->hash_ctx0);
    destroy_ctx_key(pp->hash_ctx1);
    destroy_ctx_key(pp->hash_ctx2);
    destroy_ctx_key(pp->prg_ctx);
    free(pp);
}

void key_gen(const PublicParams *pp, Key *msk)
{
    msk->key_xor_128 = malloc(sizeof(uint128_t) * KEY_LEN);
    msk->key_xor_64 = malloc(sizeof(uint64_t) * KEY_LEN);
    msk->key_maj = malloc(sizeof(uint8_t) * KEY_LEN * RING_DIM);

    // Pack the 128 ring elements of Z_2^(128+64) into one uint128
    RAND_bytes((uint8_t *)msk->key_xor_128, sizeof(uint128_t) * KEY_LEN);

    // Pack the 64 ring elements of Z_2^(128+64) into one uint64
    RAND_bytes((uint8_t *)msk->key_xor_64, sizeof(uint64_t) * KEY_LEN);

    // Store each element of Z_(MAJ_LEN+1) as a uint8_t
    RAND_bytes((uint8_t *)msk->key_maj, sizeof(uint8_t) * KEY_LEN * RING_DIM);
    for (int i = 0; i < KEY_LEN * RING_DIM; i++)
        msk->key_maj[i] &= MAJ_LEN; // equivalent to %= (MAJ_LEN+1)

    // Sample the random \Delta for the constraint key
    RAND_bytes((uint8_t *)&msk->xor_delta_128, sizeof(uint128_t));
    RAND_bytes((uint8_t *)&msk->xor_delta_64, sizeof(uint64_t));

    msk->maj_delta = malloc(sizeof(uint8_t) * RING_DIM);
    RAND_bytes((uint8_t *)msk->maj_delta, sizeof(uint8_t) * RING_DIM);
    for (int i = 0; i < RING_DIM; i++)
        msk->maj_delta[i] &= MAJ_LEN; // equivalent to %= (MAJ_LEN+1)

    // Compute the correction terms
    msk->maj_corrections = malloc(sizeof(uint8_t) * RING_DIM * NUM_COMBOS);
    compute_correction_terms(msk->maj_delta, &msk->maj_corrections[0]);
}

void constrain_key_gen(
    const PublicParams *pp,
    const Key *msk,
    Key *csk,
    const uint8_t *constraint)
{

    csk->key_xor_128 = malloc(sizeof(uint128_t) * KEY_LEN);
    csk->key_xor_64 = malloc(sizeof(uint64_t) * KEY_LEN);
    csk->key_maj = malloc(sizeof(uint8_t) * KEY_LEN * RING_DIM);
    for (size_t i = 0; i < KEY_LEN; i++)
    {
        csk->key_xor_128[i] = msk->key_xor_128[i] ^ (msk->xor_delta_128 * constraint[i]);
        csk->key_xor_64[i] = msk->key_xor_64[i] ^ (msk->xor_delta_64 * constraint[i]);
    }

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
    const uint8_t *maj_delta,
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
    // Pointers to the current inputs (separated into the xor and maj)
    const uint16_t *xor_input;
    const uint16_t *maj_input;
    uint8_t *maj_output;

    size_t xor_input_offset = 0;
    size_t maj_input_offset = 0;

    // Pointer to the current key block
    const uint8_t *maj_key_block;

    uint128_t xor_128;      // xor 128 output
    uint64_t xor_64;        // xor 64 output
    uint16_t maj[RING_DIM]; // maj output

    uint16_t i, j;
    for (size_t n = 0; n < num_ots; n++)
    {
        xor_input = &xor_inputs[xor_input_offset];
        maj_input = &maj_inputs[maj_input_offset];

        // Do the first iteration separately to initialize xor components
        xor_128 = key->key_xor_128[xor_input[0]];
        xor_64 = key->key_xor_64[xor_input[0]];
        for (i = 1; i < XOR_LEN; i++)
        {
            xor_128 ^= key->key_xor_128[xor_input[i]];
            xor_64 ^= key->key_xor_64[xor_input[i]];
        }

        xor_outputs[2 * n] = xor_128;
        xor_outputs[2 * n + 1] = xor_64;

        // Do the first iteration separately to initialize maj[i] component
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

        maj_output = &maj_outputs[n * RING_DIM];
        for (j = 0; j < RING_DIM; j++)
            maj_output[j] = maj[j] & MAJ_LEN; // equivalent to %= (MAJ_LEN +1)

        xor_input_offset += XOR_LEN;
        maj_input_offset += MAJ_LEN;
    }
}

void sender_eval(
    const PublicParams *pp,
    const Key *msk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint8_t *outputs,
    const size_t num_ots)
{

    uint128_t *xor_outputs = malloc(sizeof(uint128_t) * num_ots * 2);
    uint8_t *maj_outputs = malloc(sizeof(uint8_t) * num_ots * RING_DIM);

    common_eval(
        msk,
        xor_inputs,
        maj_inputs,
        xor_outputs,
        maj_outputs,
        num_ots);

    // Used for packing universal hash inputs
    uint8_t *uhash_in = malloc(sizeof(uint8_t) * (RING_DIM + XOR_LEN + MAJ_LEN));

    // hash_in_xor structure: [xor0, xor1, xor0+delta0, xor1+delta1]
    uint128_t *hash_in_xor = malloc(sizeof(uint128_t) * num_ots * 4);
    uint128_t *hash_out_xor = malloc(sizeof(uint128_t) * num_ots * 4);

    // hash_in_maj structure: [h(maj+delta), h(maj+2delta), ... h(maj+16*delta)]
    // where h is a universal hash to compress the ring element representation
    // into 128 near-uniform bits
    uint128_t *hash_in_maj = malloc(sizeof(uint128_t) * num_ots * (MAJ_LEN + 1));
    uint128_t *hash_out_maj = malloc(sizeof(uint128_t) * num_ots * (MAJ_LEN + 1));

    // hash_in_maj structure: [h(xor_input || maj_input)]
    // where h is a universal hash to compress the input representation
    // into 128 near-uniform bits
    uint128_t *hash_in_x = malloc(sizeof(uint128_t) * num_ots);
    uint128_t *hash_out_x = malloc(sizeof(uint128_t) * num_ots);

    // Compute the values for all xor hash components
    for (size_t n = 0; n < num_ots; n++)
    {
        // uncorrected mod2 term
        hash_in_xor[4 * n] = xor_outputs[2 * n];
        hash_in_xor[4 * n + 1] = xor_outputs[2 * n + 1];

        // corrected mod2 term
        hash_in_xor[4 * n + 2] = xor_outputs[2 * n] ^ msk->xor_delta_128;
        hash_in_xor[4 * n + 3] = xor_outputs[2 * n + 1] ^ msk->xor_delta_64;
    }

    // Define all variables used in the next loop
    const uint8_t *maj;
    const uint8_t *correction;

    uint128_t xor_out, maj_out, x_out;
    size_t i, j, index;

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

        // Compute the values for all maj hash components
        // with a universal hashing
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

        // Compute a universal hash of the input
        memcpy(&uhash_in[0], &xor_inputs[n * XOR_LEN], XOR_LEN);
        memcpy(&uhash_in[XOR_LEN], &maj_inputs[n * MAJ_LEN], MAJ_LEN);
        hash_in_x[n] = universal_hash(pp, uhash_in, XOR_LEN + MAJ_LEN);
    }

    // aes_batch_eval doesn't xor the input with the cipher output
    // but this is still sufficient to instantiate a correlation-robust hash
    // in the ideal cipher model since we truncate the output to one bit at
    // the end, as explained in: https://eprint.iacr.org/2019/074.pdf
    aes_batch_eval(pp->hash_ctx0, &hash_in_xor[0], &hash_out_xor[0], num_ots * 4);
    aes_batch_eval(pp->hash_ctx1, &hash_in_maj[0], &hash_out_maj[0], num_ots * (MAJ_LEN + 1));
    aes_batch_eval(pp->hash_ctx2, &hash_in_x[0], &hash_out_x[0], num_ots);

    // XOR all outputs together
    for (size_t n = 0; n < num_ots; n++)
    {
        size_t out_index_0 = n * NUM_COMBOS;
        size_t out_index_1 = n * NUM_COMBOS + (MAJ_LEN + 1);

        x_out = hash_out_x[n];
        for (i = 0; i < (MAJ_LEN + 1); i++)
        {
            // Note: the maj part is reused for both the lower and upper half
            maj_out = hash_out_maj[out_index_0 / 2 + i];
            xor_out = hash_out_xor[4 * n] ^ hash_out_xor[4 * n + 1];

            // Note: we truncate the output to one bit
            outputs[out_index_0 + i] = (xor_out ^ maj_out ^ x_out) & 1;

            xor_out = hash_out_xor[4 * n + 2] ^ hash_out_xor[4 * n + 3];

            // Note: we truncate the output to one bit
            outputs[out_index_1 + i] = (xor_out ^ maj_out ^ x_out) & 1;
        }
    }

    free(hash_in_xor);
    free(hash_out_xor);
    free(hash_in_maj);
    free(hash_out_maj);
    free(xor_outputs);
    free(maj_outputs);
    free(uhash_in);
    free(hash_in_x);
    free(hash_out_x);
}

void receiver_eval(
    const PublicParams *pp,
    const Key *csk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint8_t *outputs,
    const size_t num_ots)
{

    uint128_t *xor_outputs = malloc(sizeof(uint128_t) * num_ots * 2);
    uint8_t *maj_outputs = malloc(sizeof(uint8_t) * num_ots * RING_DIM);

    uint128_t *hash_out_xor = malloc(sizeof(uint128_t) * num_ots * 2);
    uint128_t *hash_in_maj = malloc(sizeof(uint128_t) * num_ots);
    uint128_t *hash_out_maj = malloc(sizeof(uint128_t) * num_ots);

    uint8_t *uhash_in = malloc(sizeof(uint8_t) * (RING_DIM + XOR_LEN + MAJ_LEN));
    uint128_t *hash_in_x = malloc(sizeof(uint128_t) * num_ots);
    uint128_t *hash_out_x = malloc(sizeof(uint128_t) * num_ots);

    common_eval(
        csk,
        xor_inputs,
        maj_inputs,
        xor_outputs,
        maj_outputs,
        num_ots);

    uint128_t xor_out, x_out;
    uint8_t *maj;

    size_t j;
    for (size_t n = 0; n < num_ots; n++)
    {
        memcpy(uhash_in, &maj_outputs[n * RING_DIM], sizeof(uint8_t) * RING_DIM);
        hash_in_maj[n] = universal_hash(pp, uhash_in, RING_DIM);

        // Compute a universal hash of the input
        memcpy(&uhash_in[0], &xor_inputs[n * XOR_LEN], XOR_LEN);
        memcpy(&uhash_in[XOR_LEN], &maj_inputs[n * MAJ_LEN], MAJ_LEN);
        hash_in_x[n] = universal_hash(pp, uhash_in, XOR_LEN + MAJ_LEN);
    }

    aes_batch_eval(pp->hash_ctx0, &xor_outputs[0], &hash_out_xor[0], num_ots * 2);
    aes_batch_eval(pp->hash_ctx1, &hash_in_maj[0], &hash_out_maj[0], num_ots);
    aes_batch_eval(pp->hash_ctx2, &hash_in_x[0], &hash_out_x[0], num_ots);

    // XOR all AES outputs together
    for (size_t n = 0; n < num_ots; n++)
    {
        x_out = hash_out_x[n];
        xor_out = hash_out_xor[2 * n] ^ hash_out_xor[2 * n + 1];

        // Note: we truncate the output to one bit
        outputs[n] = (xor_out ^ hash_out_maj[n] ^ x_out) & 1;
    }

    free(xor_outputs);
    free(maj_outputs);
    free(hash_in_maj);
    free(hash_out_maj);
    free(hash_out_xor);
    free(uhash_in);
    free(hash_in_x);
    free(hash_out_x);
}

void GenerateRandomInputs(
    const PublicParams *pp,
    uint16_t *xor_inputs,
    uint16_t *maj_inputs,
    const size_t num_ots)
{
    // Randomness we will use to generate random indices
    // we sample RAND_BUFFER more bytes in case sampled values are
    // rejected and sample RAND_OFFSET_MAX times more randomness in case the
    // sampled set of indices are not unique and the entire set is rejected
    //
    // TODO[optimization] make this extra randomness sampling more tight
    uint16_t *randomness_xor_out = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (XOR_LEN + RAND_BUFFER));
    uint16_t *randomness_xor_in = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (XOR_LEN + RAND_BUFFER));
    uint16_t *randomness_maj_in = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (MAJ_LEN + RAND_BUFFER));
    uint16_t *randomness_maj_out = malloc(sizeof(uint16_t) * RAND_OFFSET_MAX * num_ots * (MAJ_LEN + RAND_BUFFER));

    // Initialize to different values between xor and maj
    for (size_t i = 0; i < num_ots * (XOR_LEN + RAND_BUFFER); i++)
        randomness_xor_in[i] = 0;
    for (size_t i = 0; i < num_ots * (MAJ_LEN + RAND_BUFFER); i++)
        randomness_maj_in[i] = 1;

    clock_t t = clock();

    prg_eval(pp->prg_ctx, (uint128_t *)randomness_xor_in, (uint128_t *)randomness_xor_out, RAND_OFFSET_MAX * num_ots * (XOR_LEN + RAND_BUFFER) / 8);
    prg_eval(pp->prg_ctx, (uint128_t *)randomness_maj_in, (uint128_t *)randomness_maj_out, RAND_OFFSET_MAX * num_ots * (MAJ_LEN + RAND_BUFFER) / 8);

    int status = 0;

    // Offset in randomness in case of failures
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
