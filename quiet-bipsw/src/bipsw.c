#include "prf.h"
#include "prg.h"
#include "bipsw.h"
#include "utils.h"
#include "params.h"

#include <stdlib.h>
#include <openssl/rand.h>

#ifdef AVX
#include <immintrin.h>
#endif

void pp_gen(
    PublicParams *pp,
    const size_t key_len)
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
}

void pp_free(PublicParams *pp)
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
// input, which has a negligible probability of occurring in QuietOT).
void key_gen(const PublicParams *pp, Key *msk)
{
    // CPRF master key (in CRT form with mod 2 and mod 3 parts)
    msk->key_2 = malloc(sizeof(uint128_t) * pp->key_len);
    msk->key_3 = malloc(sizeof(uint128_t) * pp->key_len * 2);

    RAND_bytes((uint8_t *)msk->key_2, sizeof(uint128_t) * pp->key_len);

    // Generate unbiased values mod 3 via rejection sampling
    uint8_t *rand_3 = malloc(sizeof(uint8_t) * pp->key_len * RING_DIM);
    sample_mod_3(rand_3, pp->key_len * RING_DIM);

    for (size_t i = 0; i < pp->key_len; i++)
    {
        // Valid representations are (0,0), (0,1), and (1,1)
        // 0 --> (0,0)
        // 1 --> (0,1)
        // 2 --> (1,1)

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

    // Compute the \delta offsets that we use in sender_eval
    compute_correction_terms(msk, msk->delta);
}

// Constrain generates a constrained key (in CRT form)
// consisting of KEY_LEN elements of the ring Z_6^RING_DIM.
// - Inputs: a constraint z (in CRT form) consisting of KEY_LEN element of Z_6
//           and one random element (Delta) of the ring Z_6^RING_DIM.
// - Outputs: constrained key of the form msk + \Delta*z
void constrain_key_gen(
    const PublicParams *pp,
    const Key *msk,
    Key *csk,
    const uint8_t *constraint)
{

    const size_t key_len = pp->key_len;
    csk->key_2 = malloc(sizeof(uint128_t) * key_len);
    csk->key_3 = malloc(sizeof(uint128_t) * key_len * 2);

    uint128_t prod;

    // To compute \Delta * z, we compute the "tensor product" between \Delta
    // and z (the constraint) which gives us a vector of KEY_LEN (Z_6^RING_DIM)
    // elements.

    // compute the Z_2 part
    for (size_t i = 0; i < key_len; i++)
    {
        csk->key_2[i] = msk->key_2[i];
        for (size_t j = 0; j < RING_DIM; j++)
        {
            prod = ((msk->delta[j] * constraint[i]) % 6) % 2;

            // pack each ring element into one uint128_t
            csk->key_2[i] ^= (prod << j);
        }
    }

    // compute the Z_3 part
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
    const PublicParams *pp,
    const Key *key,
    const KeyCache *key_cache,
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

    // Allocate aligned memory for AVX512
    posix_memalign((void **)&key_cache->cache_2_avx, 64, mem_size);
    posix_memalign((void **)&key_cache->cache_3_avx, 64, 2 * mem_size);

    uint128_t *avx_store;
    posix_memalign((void **)&avx_store, 64, 4 * sizeof(uint128_t));

    // TODO [optimization]: have the keys be stored in this format
    // correctly without having to copy. After some benchmarks,
    // however, optimizing this part will leads to only minor perf improvements.
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

    size_t input_offset = 0; // offset to the current input ring element vector
    size_t cache_offset;     // offset to the current key ring element in cache

    uint8_t i, j;
    for (size_t n = 0; n < num_ots;)
    {
        x = &inputs[input_offset];

        // Compute inner product between CPRF key and current input
        // using the cached inner product blocks

#ifdef AVX

        sum_2_avx = _mm512_setzero_si512();
        sum_3h_avx = _mm512_setzero_si512();
        sum_3l_avx = _mm512_setzero_si512();

        cache_offset = 0;
        for (i = 0; i < num_blocks; i++)
        {
            // compute XOR part
            sum_2_avx = _mm512_xor_si512(
                sum_2_avx,
                key_cache->cache_2_avx[cache_offset + x[i]]);

            // (a[1] ^ b[0])
            tmp_1 = _mm512_xor_si512(
                sum_3l_avx,
                key_cache->cache_3_avx[2 * cache_offset + 2 * x[i]]);

            // (a[0] ^ b[1])
            tmp_2 = _mm512_xor_si512(
                sum_3h_avx,
                key_cache->cache_3_avx[2 * cache_offset + 2 * x[i] + 1]);

            // (a[1] ^ b[0]) & (a[0] ^ b[1]);
            sum_3h_avx = _mm512_and_si512(tmp_1, tmp_2);

            // (a[1] ^ b[1])
            tmp_1 = _mm512_xor_si512(
                sum_3l_avx,
                key_cache->cache_3_avx[2 * cache_offset + 2 * x[i] + 1]);

            // (a[0] ^ b[1] ^ b[0]);
            tmp_2 = _mm512_xor_si512(
                tmp_2,
                key_cache->cache_3_avx[2 * cache_offset + 2 * x[i]]);

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
            // compute the mod2 part of the inner product
            sum_2 ^= key_cache->cache_2[cache_offset + x[i]];

            // compute the mod3 part of the inner product
            inplace_mod_3_addr(
                &sum_3[0], &key_cache->cache_3[2 * cache_offset + 2 * x[i]]);
            cache_offset += cache_block_size;
        }

        outputs_2[n] = sum_2;
        outputs_3[2 * n] = sum_3[0];
        outputs_3[2 * n + 1] = sum_3[1];

        n++;
        input_offset += num_blocks;
#endif
    } // end of loop

#ifdef AVX
    free(key_cache->cache_2_avx);
    free(key_cache->cache_3_avx);
    free(avx_store);
#endif
}

void sender_eval(
    const PublicParams *pp,
    const Key *msk,
    const KeyCache *msk_cache,
    const uint16_t *inputs,
    uint8_t *outputs,
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

    uint128_t *chunk_hash_in;
    uint128_t *output_2;
    uint128_t *output_3;

    uint128_t *hash_in = malloc(sizeof(uint128_t) * num_ots * 6 * 3);
    uint128_t *hash_out = malloc(sizeof(uint128_t) * num_ots * 6 * 3);

    size_t output_offset = 0;
    for (size_t n = 0; n < num_ots; n++)
    {
        chunk_hash_in = &hash_in[n * 6 * 3];
        output_2 = &outputs_2[n];
        output_3 = &outputs_3[2 * n];

        uint8_t idx_2, idx_30, idx_31;

        // we pack 128-log_3(2^128) bits of the input into the Z3 blocks
        // before feeding the whole thing into AES to instantiate H(k||x)
        // where H is a random oracle.
        // Note: we pack 6*16 = 96 bits of the input, where 16 = CACHE_BITS
        // TODO: remove dependency on CACHE_BITS = 16
        size_t idx_in_chunk = 6 * n;

        // Subtract the correction terms
        for (size_t i = 0; i < 6; i++)
        {
            // Indices of the mod2 and mod3 components
            idx_2 = 3 * i;
            idx_30 = 3 * i + 1;
            idx_31 = 3 * i + 2;

            chunk_hash_in[idx_2] = output_2[0] ^ (msk->correction_2 * (i % 2));
            chunk_hash_in[idx_30] = output_3[0];
            chunk_hash_in[idx_31] = output_3[1];

            inplace_mod_3_subr(&chunk_hash_in[idx_30], &msk->corrections_3[2 * i]);

            // Append the input string to the last chunks of the mod3 components
            chunk_hash_in[idx_30] ^= inputs[idx_in_chunk];
            chunk_hash_in[idx_30] <<= 16; // 16 = CACHE_BITS
            chunk_hash_in[idx_30] ^= (inputs[idx_in_chunk + 1]);
            chunk_hash_in[idx_30] <<= 16;
            chunk_hash_in[idx_30] ^= (inputs[idx_in_chunk + 2]);

            chunk_hash_in[idx_31] ^= inputs[idx_in_chunk + 3];
            chunk_hash_in[idx_31] <<= 16;
            chunk_hash_in[idx_31] ^= (inputs[idx_in_chunk + 4]);
            chunk_hash_in[idx_31] <<= 16;
            chunk_hash_in[idx_31] ^= (inputs[idx_in_chunk + 5]);
        }
    }

    // aes_batch_eval doesn't xor the input with the cipher output
    // but this is still sufficient to instantiate a correlation-robust hash
    // in the ideal cipher model since we truncate the output to one bit at
    // the end, as explained in: https://eprint.iacr.org/2019/074.pdf
    aes_batch_eval(pp->hash_ctx, &hash_in[0], &hash_out[0], num_ots * 6 * 3);

    // Xor the output blocks and truncate to one bit
    for (size_t n = 0; n < num_ots * 6; n++)
        outputs[n] = (hash_out[3 * n] ^ hash_out[3 * n + 1] ^ hash_out[3 * n + 2]) & 1;

    free(outputs_2);
    free(outputs_3);
    free(hash_in);
    free(hash_out);
}

void receiver_eval(
    const PublicParams *pp,
    const Key *csk,
    const KeyCache *csk_cache,
    const uint16_t *inputs,
    uint8_t *outputs,
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

    uint128_t *hash_in = malloc(sizeof(uint128_t) * num_ots * 3);
    uint128_t *hash_out = malloc(sizeof(uint128_t) * num_ots * 3);

    size_t idx_2, idx_30, idx_31;
    size_t idx_in_chunk;
    for (size_t n = 0; n < num_ots; n++)
    {
        // indices of the mod2 and mod3 components
        idx_2 = 3 * n;
        idx_30 = 3 * n + 1;
        idx_31 = 3 * n + 2;

        hash_in[idx_2] = outputs_2[n];
        hash_in[idx_30] = outputs_3[2 * n];
        hash_in[idx_31] = outputs_3[2 * n + 1];

        idx_in_chunk = 6 * n;
        hash_in[idx_30] ^= inputs[idx_in_chunk];
        hash_in[idx_30] <<= 16;
        hash_in[idx_30] ^= (inputs[idx_in_chunk + 1]);
        hash_in[idx_30] <<= 16;
        hash_in[idx_30] ^= (inputs[idx_in_chunk + 2]);

        hash_in[idx_31] ^= inputs[idx_in_chunk + 3];
        hash_in[idx_31] <<= 16;
        hash_in[idx_31] ^= (inputs[idx_in_chunk + 4]);
        hash_in[idx_31] <<= 16;
        hash_in[idx_31] ^= (inputs[idx_in_chunk + 5]);
    }

    // See comment about this in sender_eval
    aes_batch_eval(pp->hash_ctx, &hash_in[0], &hash_out[0], num_ots * 3);

    // Xor the output blocks and truncate to one bit
    for (size_t n = 0; n < num_ots; n++)
        outputs[n] = (hash_out[3 * n] ^ hash_out[3 * n + 1] ^ hash_out[3 * n + 2]) & 1;

    free(outputs_2);
    free(outputs_3);
    free(hash_in);
    free(hash_out);
}

// Pre-compute corrections terms
void compute_correction_terms(
    Key *msk,
    const uint8_t *delta)
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
            continue;
        }

        packed_3[0] = 0;
        packed_3[1] = 0;

        uint128_t mask = 1;
        for (size_t j = 0; j < RING_DIM; j++)
        {

            prod = 3 - ((i * delta[j]) % 6) % 3; // Need to negate (mod 3)

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
