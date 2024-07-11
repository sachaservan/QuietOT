#include "prf.h"
#include "prg.h"
#include "bipsw.h"
#include "utils.h"
#include "params.h"
#include "polymur.h"

#include <stdlib.h>
#include <openssl/rand.h>

#ifdef AVX
#include <immintrin.h>
#endif

void pp_gen(
    struct PublicParams *pp,
    size_t key_len)
{
    pp->key_len = key_len;

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

    PolymurHashParams p0, p1;
    polymur_init_params_from_seed(&p0, POLYMUR_SEED0);
    polymur_init_params_from_seed(&p1, POLYMUR_SEED1);
    pp->polymur_params0 = p0;
    pp->polymur_params0 = p1;
}

void pp_free(struct PublicParams *pp)
{
    destroy_ctx_key(pp->hash_ctx);
    destroy_ctx_key(pp->prg_ctx);
    free(pp);
}

// key_gen generates a master key (in CRT form)
// consisting of KEY_LEN elements of the ring Z_6^RING_DIM.
//
// TODO: implement the k_0 part of the protocol
// need to include secret offset k_0 in both msk and csk
// (k_0 is only required to avoid having a deterministic output on the all-zero
// input, which has a negligible probability of occurring).
void key_gen(struct PublicParams *pp, struct Key *msk)
{
    // CPRF master key (in CRT form with mod 2 and mod 3 parts)
    msk->key_2 = malloc(sizeof(uint128_t) * pp->key_len);
    msk->key_3 = malloc(sizeof(uint128_t) * pp->key_len * 2);

    RAND_bytes((uint8_t *)msk->key_2, sizeof(uint128_t) * pp->key_len);

    // generate unbiased values mod 3 via rejection sampling
    uint8_t *rand_3 = malloc(sizeof(uint8_t) * pp->key_len * RING_DIM);
    sample_mod_3(rand_3, pp->key_len * RING_DIM);

    for (size_t i = 0; i < pp->key_len; i++)
    {
        // valid representations are (0,0), (0,1), and (1,1)
        // 0 --> (0,0)  1 --> (0,1)  2 --> (1,1)

        msk->key_3[2 * i] = 0;
        msk->key_3[2 * i + 1] = 0;
        uint128_t mask = 1;
        for (size_t j = 0; j < RING_DIM; j++)
        {

            if (rand_3[i * RING_DIM + j] == 2)
            {
                // set to (1,1)
                msk->key_3[2 * i] |= mask;
                msk->key_3[2 * i + 1] |= mask;
            }
            else if (rand_3[i + j] == 1)
            {
                // set to (0,1)
                msk->key_3[2 * i + 1] |= mask;
            }

            mask = mask << 1;
        }
    }

    // Sample the random Delta for the constraint key
    msk->delta = malloc(sizeof(uint8_t) * RING_DIM);
    sample_mod_6(msk->delta, RING_DIM);

    compute_correction_terms(msk, msk->delta);
}

// Constrain generates a constrained key (in CRT form)
// consisting of KEY_LEN elements of the ring Z_6^RING_DIM.
// - Inputs: a constraint (in CRT form) consisting of KEY_LEN element of Z_6
//           and one random element (Delta) of the ring Z_6^RING_DIM.
// - Outputs: constrained key of the form msk + \Delta*constraint
//
// TODO: implement the k_0 part of the protocol
// need to include secret offset k_0 in both msk and csk
// (k_0 is only required to avoid having a deterministic output on the all-zero
// input, which has a negligible probability of occurring).
void constrain_key_gen(
    struct PublicParams *pp,
    struct Key *msk,
    struct Key *csk,
    uint8_t *constraint)
{

    size_t key_len = pp->key_len;
    csk->key_2 = malloc(sizeof(uint128_t) * key_len);
    csk->key_3 = malloc(sizeof(uint128_t) * key_len * 2);

    uint128_t prod;

    // To compute \Delta * z, we compute the "tensor product" between \Delta
    // and z (the constraint) which gives us a vector of KEY_LEN (Z_6^RING_DIM) elements.
    for (size_t i = 0; i < key_len; i++)
    {
        csk->key_2[i] = msk->key_2[i];
        for (size_t j = 0; j < RING_DIM; j++)
        {
            prod = ((msk->delta[j] * constraint[i]) % 6) % 2;

            // pack each ring element into a uint128
            csk->key_2[i] ^= (prod << j);
        }
    }

    uint128_t packed_3[2];
    for (size_t i = 0; i < key_len; i++)
    {
        csk->key_3[2 * i] = msk->key_3[2 * i];
        csk->key_3[2 * i + 1] = msk->key_3[2 * i + 1];

        packed_3[0] = 0;
        packed_3[1] = 0;

        uint128_t mask = 1;
        for (size_t j = 0; j < RING_DIM; j++)
        {
            prod = ((msk->delta[j] * constraint[i]) % 6) % 3;

            if (prod == 2)
            {
                // set to (1,1)
                packed_3[0] |= mask;
                packed_3[1] |= mask;
            }
            else if (prod == 1)
            {
                // set to (0,1)
                packed_3[1] |= mask;
            }

            mask = mask << 1;
        }

        inplace_mod_3_addr(&csk->key_3[2 * i], &packed_3[0]);
    }
}

static inline void common_eval(
    struct PublicParams *pp,
    struct Key *key,
    struct KeyCache *key_cache,
    const uint16_t *inputs,
    uint128_t *outputs_2,
    uint128_t *outputs_3,
    const size_t num_ots)
{
    const size_t cache_block_size = (1UL << CACHE_BITS);
    const size_t num_blocks = KEY_LEN / CACHE_BITS;

    const uint16_t *x; // pointers to the current positions in the input stream

#ifdef AVX
    size_t mem_size = num_blocks * cache_block_size * sizeof(__m512i);
    __m512i * key_cache->cache_2_avx;
    __m512i * key_cache->cache_3_avx;

    // allocate aligned memory for AVX512
    posix_memalign((void **)&key_cache->cache_2_avx, 64, mem_size);
    posix_memalign((void **)&key_cache->cache_3_avx, 64, 2 * mem_size);

    uint128_t *avx_store;
    posix_memalign((void **)&avx_store, 64, 4 * sizeof(uint128_t));

    // TODO [optimization]: have the keys be stored in this format
    // correctly without having to copy. After some benchmarks,
    // however, optimizing this part will leads to only minor results.
    for (size_t i = 0; i < num_blocks * cache_block_size; i++)
    {
        avx_store[0] = key_cache->cache_2[0 * KEY_LEN + i];
        avx_store[1] = key_cache->cache_2[1 * KEY_LEN + i];
        avx_store[2] = key_cache->cache_2[2 * KEY_LEN + i];
        avx_store[3] = key_cache->cache_2[3 * KEY_LEN + i];
        key_cache->cache_2_avx[i] = _mm512_load_si512((__m512i *)(avx_store));

        avx_store[0] = key_cache->cache_3[0 * KEY_LEN + 2 * i];
        avx_store[1] = key_cache->cache_3[2 * KEY_LEN + 2 * i];
        avx_store[2] = key_cache->cache_3[4 * KEY_LEN + 2 * i];
        avx_store[3] = key_cache->cache_3[6 * KEY_LEN + 2 * i];
        key_cache->cache_3_avx[2 * i] = _mm512_load_si512((__m512i *)(avx_store));

        avx_store[0] = key_cache->cache_3[0 * KEY_LEN + 2 * i + 1];
        avx_store[1] = key_cache->cache_3[2 * KEY_LEN + 2 * i + 1];
        avx_store[2] = key_cache->cache_3[4 * KEY_LEN + 2 * i + 1];
        avx_store[3] = key_cache->cache_3[6 * KEY_LEN + 2 * i + 1];
        key_cache->cache_3_avx[2 * i + 1] = _mm512_load_si512((__m512i *)(avx_store));
    }

    __m512i sum_2_avx = _mm512_setzero_si512();
    __m512i sum_3h_avx = _mm512_setzero_si512();
    __m512i sum_3l_avx = _mm512_setzero_si512();
    __m512i tmp_1, tmp_2;
#endif

    uint128_t sum_2 = 0;      // we pack RING_DIM bits in uint128_t
    uint128_t sum_3[2] = {0}; // we pack RING_DIM Z3 elements in two uint128_t

    size_t input_offset = 0;
    size_t cache_offset;

    clock_t t = clock();

    uint8_t i, j;
    for (size_t n = 0; n < num_ots;)
    {
        x = &inputs[input_offset];

        // compute inner product between cprf_key and current input
        // using the cached inner product blocks

#ifdef AVX

        sum_2_avx = _mm512_setzero_si512();
        sum_3h_avx = _mm512_setzero_si512();
        sum_3l_avx = _mm512_setzero_si512();

        cache_offset = 0;
        for (i = 0; i < num_blocks; i++)
        {
            // compute XOR part
            sum_2_avx = _mm512_xor_si512(sum_2_avx, key_cache->cache_2_avx[cache_offset + x[i]]);

            // (a[1] ^ b[0])
            tmp_1 = _mm512_xor_si512(sum_3l_avx, key_cache->cache_3_avx[2 * cache_offset + 2 * x[i]]);

            // (a[0] ^ b[1])
            tmp_2 = _mm512_xor_si512(sum_3h_avx, key_cache->cache_3_avx[2 * cache_offset + 2 * x[i] + 1]);

            // (a[1] ^ b[0]) & (a[0] ^ b[1]);
            sum_3h_avx = _mm512_and_si512(tmp_1, tmp_2);

            // (a[1] ^ b[1])
            tmp_1 = _mm512_xor_si512(sum_3l_avx, key_cache->cache_3_avx[2 * cache_offset + 2 * x[i] + 1]);

            // (a[0] ^ b[1] ^ b[0]);
            tmp_2 = _mm512_xor_si512(tmp_2, key_cache->cache_3_avx[2 * cache_offset + 2 * x[i]]);

            sum_3l_avx = _mm512_or_si512(tmp_1, tmp_2);

            cache_offset += cache_block_size;
        }

        _mm512_store_si512((__m512i *)(&outputs_2[n]), sum_2_avx);
        _mm512_store_si512((__m512i *)(avx_store), sum_3h_avx);
        outputs_3[2 * n + 0] = avx_store[0];
        outputs_3[2 * n + 2] = avx_store[1];
        outputs_3[2 * n + 4] = avx_store[2];
        outputs_3[2 * n + 6] = avx_store[3];

        _mm512_store_si512((__m512i *)(avx_store), sum_3l_avx);
        outputs_3[2 * n + 1] = avx_store[0];
        outputs_3[2 * n + 3] = avx_store[1];
        outputs_3[2 * n + 5] = avx_store[2];
        outputs_3[2 * n + 7] = avx_store[3];

        n += 4;
        input_offset += num_blocks;

#else

        sum_2 = 0;
        sum_3[0] = 0;
        sum_3[1] = 0;

        cache_offset = 0;
        for (i = 0; i < num_blocks; i++)
        {
            sum_2 ^= key_cache->cache_2[cache_offset + x[i]];
            inplace_mod_3_addr(&sum_3[0], &key_cache->cache_3[2 * cache_offset + 2 * x[i]]);
            cache_offset += cache_block_size;
        }

        outputs_2[n] = sum_2;
        outputs_3[2 * n] = sum_3[0];
        outputs_3[2 * n + 1] = sum_3[1];

        n++;
        input_offset += num_blocks;
#endif
    }

    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

#ifdef AVX
    free(key_cache->cache_2_avx);
    free(key_cache->cache_3_avx);
    free(avx_store);
#endif
}

void sender_eval(
    struct PublicParams *pp,
    struct Key *msk,
    struct KeyCache *msk_cache,
    const uint16_t *inputs,
    uint128_t *outputs,
    const size_t num_ots)
{

    uint128_t *outputs_2;
    uint128_t *outputs_3;
    posix_memalign((void **)&outputs_2, 64, num_ots * sizeof(uint128_t));
    posix_memalign((void **)&outputs_3, 64, 2 * num_ots * sizeof(uint128_t));

    common_eval(
        pp,
        msk,
        msk_cache,
        inputs,
        outputs_2,
        outputs_3,
        num_ots);

    uint128_t *output;
    uint128_t *output_2;
    uint128_t *output_3;
    uint128_t uhash_in[3];

    uint128_t *hash_in = malloc(sizeof(uint128_t) * num_ots * 6);

    size_t output_offset = 0;
    for (size_t n = 0; n < num_ots; n++)
    {
        output = &hash_in[n * 6];
        output_2 = &outputs_2[n];
        output_3 = &outputs_3[2 * n];

        // subtract the correction terms
        for (size_t i = 0; i < 6; i++)
        {
            uhash_in[0] = output_2[0] ^ (msk->correction_2 * (i % 2));

            uhash_in[1] = output_3[0];
            uhash_in[2] = output_3[1];

            // TODO [BUG]: fix this weirdness.
            // Basically there is some issue with the way the corrections are
            // computed for the Z3 case. It's unclear why the indexing is
            // swapped in this way. Removing these if statements will improve
            // efficiency but currently this is a workaround.
            if (i == 0)
                inplace_mod_3_subr(&uhash_in[1], &msk->corrections_3[0]);
            else if (i == 1 || i == 4)
                inplace_mod_3_subr(&uhash_in[1], &msk->corrections_3[4]);
            else if (i == 2 || i == 5)
                inplace_mod_3_subr(&uhash_in[1], &msk->corrections_3[2]);

            output[i] = universal_hash_3(pp, &uhash_in[0]);
        }
    }

    prf_batch_eval(pp->hash_ctx, &hash_in[0], &outputs[0], num_ots * 6);

    free(outputs_2);
    free(outputs_3);
    free(hash_in);
}

void receiver_eval(
    struct PublicParams *pp,
    struct Key *csk,
    struct KeyCache *csk_cache,
    const uint16_t *inputs,
    uint128_t *outputs,
    const size_t num_ots)
{
    uint128_t *outputs_2;
    uint128_t *outputs_3;
    posix_memalign((void **)&outputs_2, 64, num_ots * sizeof(uint128_t));
    posix_memalign((void **)&outputs_3, 64, 2 * num_ots * sizeof(uint128_t));

    common_eval(
        pp,
        csk,
        csk_cache,
        inputs,
        outputs_2,
        outputs_3,
        num_ots);

    uint128_t *hash_in = malloc(sizeof(uint128_t) * num_ots);
    uint128_t uhash_in[3];
    for (size_t n = 0; n < num_ots; n++)
    {
        uhash_in[0] = outputs_2[n];
        uhash_in[1] = outputs_3[2 * n];
        uhash_in[2] = outputs_3[2 * n + 1];

        hash_in[n] = universal_hash_3(pp, &uhash_in[0]);
    }

    prf_batch_eval(pp->hash_ctx, &hash_in[0], &outputs[0], num_ots);

    free(outputs_2);
    free(outputs_3);
    free(hash_in);
}

// Pre-compute corrections terms
void compute_correction_terms(
    struct Key *msk,
    uint8_t *delta)
{
    msk->corrections_3 = malloc(sizeof(uint128_t) * 6 * 2);

    uint128_t prod;
    uint128_t packed_2;
    uint128_t packed_3[2];

    packed_2 = 0;
    for (size_t j = 0; j < RING_DIM; j++)
    {
        prod = delta[j] % 2;
        packed_2 |= (prod << j);
    }
    msk->correction_2 = packed_2;

    for (size_t i = 0; i < 6; i++)
    {
        if (i == 0)
        {
            msk->corrections_3[2 * i] = 0;
            msk->corrections_3[2 * i + 1] = 0;
        }

        packed_3[0] = 0;
        packed_3[1] = 0;

        uint128_t mask = 1;
        for (size_t j = 0; j < RING_DIM; j++)
        {

            prod = ((i * delta[j]) % 6) % 3;

            if (prod == 2)
            {
                // set to (1,1)
                packed_3[0] |= mask;
                packed_3[1] |= mask;
            }
            else if (prod == 1)
            {
                // set to (0,1)
                packed_3[1] |= mask;
            }

            mask = mask << 1;
        }

        msk->corrections_3[2 * i] = packed_3[0];
        msk->corrections_3[2 * i + 1] = packed_3[1];
    }
}
