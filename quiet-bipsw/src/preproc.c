#include "../include/bipsw.h"
#include "utils.h"
#include "params.h"

#include <string.h>

// Pre-computes inner products and coefficients used in CPRF evaluation.
void compute_key_caches(
    const PublicParams *pp,
    const Key *key,
    KeyCache *key_cache,
    const size_t mem_size)
{

    uint128_t *cache_2;
    uint128_t *cache_3;
    posix_memalign((void **)&cache_2, 64, mem_size);
    posix_memalign((void **)&cache_3, 64, 2 * mem_size);

    // Note: caches need to be initialized to zero.
    memset(cache_2, 0, mem_size);
    memset(cache_3, 0, 2 * mem_size);

    key_cache->cache_2 = cache_2;
    key_cache->cache_3 = cache_3;

    size_t num_blocks = pp->key_len / CACHE_BITS;
    size_t block_size = CACHE_BITS;

    for (size_t b = 0; b < num_blocks; b++)
    {
        // go to next block of block_size ring elements
        uint128_t *k_2 = &key->key_2[b * block_size];
        uint128_t *k_3 = &key->key_3[2 * b * block_size];

        for (size_t x = 0; x < (1UL << CACHE_BITS); x++)
        {
            uint128_t *sums_2 = &cache_2[b * (1UL << CACHE_BITS) + x];
            uint128_t *sums_3 = &cache_3[2 * b * (1UL << CACHE_BITS) + 2 * x];

            // compute inner product with the current n value
            for (size_t i = 0; i < CACHE_BITS; i++)
            {
                if (((x >> i) & 1) == 0)
                    continue;

                sums_2[0] ^= k_2[i];

                // do bit-sliced mod 3 addition
                inplace_mod_3_addr(&sums_3[0], &k_3[2 * i]);
            }
        }
    }
}
