#ifndef _UTILS
#define _UTILS

#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>

#include "params.h"
#include "polymur.h"

// outputs 1 if there are no duplicate indicies in arr
// outputs 0 otherwise
static inline int all_unique_indices(uint16_t *arr, size_t n)
{
    uint16_t val, byte_idx;
    uint8_t mask;
    uint8_t bit_vec[KEY_LEN / 8] = {0};

    for (size_t i = 0; i < n; i++)
    {
        val = arr[i];
        byte_idx = val / 8;
        mask = 1 << (val % 8);

        // Check if the bit for 'val' is already set
        if (bit_vec[byte_idx] & mask)
            return 0; // duplicate found

        // Set the bit for 'val'
        bit_vec[byte_idx] |= mask;
    }

    return 1; // No duplicates found
}

// Samples num random values between 0 and max;
// returns -1 if not enough randomness provided or if not distinct
static inline int sample_random_distinct_key_indices(
    uint16_t *randomness,
    uint16_t *rand_indices,
    size_t num)
{
    size_t i, j;
    i = 0;
    j = 0;
    while (i < num)
    {
        // WARNING: assumes that KEY_LEN is a power of 2;
        // otherwise need to perform rejection sampling
        rand_indices[i++] = randomness[j] & (KEY_LEN - 1); // if power of 2
        j++;
    }

    return all_unique_indices(rand_indices, num);
}

// Computes a universal hash using the polymur hash function
// To get a 128 bit hash, we concatenate the output of two independent
// polymur hashes each outputting 64 bits
static inline uint128_t universal_hash(
    const PublicParams *pp,
    uint8_t *in,
    size_t len)
{
    // Compute a universal hash to compress the input into a uint128
    // integer that we then feed into the random oracle.
    // Because polymur_hash outputs a uint64, we hash twice with
    // different keys and concatenate the results
    uint128_t out = polymur_hash(
        in, len, &pp->polymur_params0, POLYMUR_TWEAK);
    out = out << 64;
    out |= polymur_hash(
        in, len, &pp->polymur_params1, POLYMUR_TWEAK);
    return out;
}

// For debugging purposes
static uint128_t hex_to_uint_128(const char *hex_str)
{
    uint128_t result = 0;
    size_t len = strlen(hex_str);

    for (size_t i = 0; i < len; i++)
    {
        char c = hex_str[i];
        uint8_t digit;

        if (c >= '0' && c <= '9')
        {
            digit = c - '0';
        }
        else if (c >= 'a' && c <= 'f')
        {
            digit = c - 'a' + 10;
        }
        else if (c >= 'A' && c <= 'F')
        {
            digit = c - 'A' + 10;
        }
        else
        {
            return 0;
        }
        result = (result << 4) | digit;
    }

    return result;
}

#endif
