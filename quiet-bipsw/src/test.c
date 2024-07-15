#include "bipsw.h"
#include "prf.h"
#include "prg.h"
#include "utils.h"
#include "params.h"

#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

uint64_t
randIndex(uint64_t max)
{
    srand(time(NULL));
    return ((uint64_t)rand()) % ((uint64_t)max);
}

double benchmarkOTs()
{
    size_t num_ots = NUM_OTS;
    size_t key_len = KEY_LEN;
    size_t num_inputs = num_ots;
    size_t num_outputs = NUM_OTS;
#ifdef AVX
    num_ots = 4 * NUM_OTS;
    key_len = 4 * KEY_LEN; // do 4 keys in parallel
    num_inputs = NUM_OTS;
    num_outputs = 4 * NUM_OTS;
#endif

    // **********************************
    // Generate public parameters
    // **********************************
    PublicParams *pp = malloc(sizeof(PublicParams));
    pp_gen(pp, key_len);

    // **********************************
    // Generate CPRF master key
    // **********************************
    Key *msk = malloc(sizeof(Key));
    key_gen(pp, msk);

    // **********************************
    // Generate key caches
    // (pre-computed values for inner products)
    // **********************************
    size_t mem_size = (1UL << CACHE_BITS) * (key_len / CACHE_BITS) * sizeof(uint128_t);
    KeyCache *msk_cache = malloc(sizeof(KeyCache));
    compute_key_caches(pp, msk, msk_cache, mem_size);

    // **********************************
    // Generate constrained CPRF key
    // **********************************

    // Sample a random constraint
    uint8_t *constraint = malloc(sizeof(uint8_t) * key_len);
    sample_mod_6(constraint, RING_DIM);

    // Compute the constrained key
    Key *csk = malloc(sizeof(Key));
    constrain_key_gen(pp, msk, csk, constraint);

    KeyCache *csk_cache = malloc(sizeof(KeyCache));
    compute_key_caches(pp, csk, csk_cache, mem_size);

    // **********************************
    // Benchmarks and tests
    // **********************************
    uint16_t *inputs = (uint16_t *)malloc(sizeof(uint16_t) * (KEY_LEN / CACHE_BITS) * num_inputs);
    uint8_t *outputs_sender;
    uint8_t *outputs_receiver;
    posix_memalign((void **)&outputs_sender, 64, num_outputs * 6 * sizeof(uint8_t));
    posix_memalign((void **)&outputs_receiver, 64, num_outputs * sizeof(uint8_t));

    clock_t t = clock();

    // step 1: compute the random inputs via PRG
    size_t input_size_128_blocks = (KEY_LEN / CACHE_BITS) * num_inputs / 8;
    prg_eval(pp->prg_ctx, (uint128_t *)inputs, (uint128_t *)inputs, input_size_128_blocks);

    // step 2: compute CPRF on random inputs
    sender_eval(pp,
                msk,
                msk_cache,
                inputs,
                outputs_sender,
                num_ots);

    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("Time (total) %f ms\n", time_taken);

    receiver_eval(pp,
                  csk,
                  csk_cache,
                  inputs,
                  outputs_receiver,
                  num_ots);

    // **********************************
    // Test correctness and generate stats
    // **********************************

    int dist[6] = {0};     // output index distribution
    double not_found = 0;  // number of failures (no matching value found)
    int err_hist[6] = {0}; // histogram of where errors ocurred

#ifdef AVX
    for (size_t n = 0; n < num_ots; n += 4)
    {
        // TODO: Test all four AVX outputs (currently only testing the first one)
        // by considering the input n/4 and incrementing n by 4

        // compute weak PRF output (inner product between input and constraint)
        uint16_t *input = &inputs[n / 4 * (KEY_LEN / CACHE_BITS)];
        uint16_t input_block;
        size_t in_idx = 0;
        size_t idx = 0;
        size_t shift = 0;
        for (size_t i = 0; i < KEY_LEN; i++)
        {
            if (shift % CACHE_BITS == 0)
            {
                shift = 0;
                input_block = input[in_idx];
                in_idx++;
            }

            idx += constraint[i] * ((input_block >> shift) & 1);
            shift++;
        }

        idx %= 6;    // index of the receiver's value in the sender's list
        dist[idx]++; // keep a count of all seen indices

        if (outputs_sender[n * 6 + idx] != outputs_receiver[n])
        {
            not_found++;
            err_hist[idx]++;
        }
    }

    // printf("Index dist: (%i, %i, %i, %i, %i, %i)\n", dist[0], dist[1], dist[2], dist[3], dist[4], dist[5]);

    if (not_found != 0)
    {
        printf("ERROR: %f fraction of values not found!\n", not_found / (double)num_ots);
        printf("DIST: (%i, %i, %i, %i, %i, %i)\n", err_hist[0], err_hist[1], err_hist[2], err_hist[3], err_hist[4], err_hist[5]);
        printf("FAIL\n\n");
    }
    else
    {
        printf("PASS\n\n");
    }
#else
    for (size_t n = 0; n < num_ots; n++)
    {
        // compute weak PRF output (inner product between input and constraint)
        uint16_t *input = &inputs[n * (KEY_LEN / CACHE_BITS)];
        uint16_t input_block;
        size_t in_idx = 0;
        size_t idx = 0;
        size_t shift = 0;
        for (size_t i = 0; i < KEY_LEN; i++)
        {
            if (shift % CACHE_BITS == 0)
            {
                shift = 0;
                input_block = input[in_idx];
                in_idx++;
            }

            idx += constraint[i] * ((input_block >> shift) & 1);
            shift++;
        }

        idx %= 6;    // index of the receiver's value in the sender's list
        dist[idx]++; // keep a count of all seen indices

        if (outputs_sender[n * 6 + idx] != outputs_receiver[n])
        {
            not_found++;
            err_hist[idx]++;
        }
    }

    // printf("Index dist: (%i, %i, %i, %i, %i, %i)\n", dist[0], dist[1], dist[2], dist[3], dist[4], dist[5]);

    if (not_found != 0)
    {
        printf("ERROR: %f fraction of values not found!\n", not_found / (double)num_ots);
        printf("DIST: (%i, %i, %i, %i, %i, %i)\n", err_hist[0], err_hist[1], err_hist[2], err_hist[3], err_hist[4], err_hist[5]);
        printf("FAIL\n\n");
    }
    else
    {
        printf("PASS\n\n");
    }
#endif

    pp_free(pp);
    free(outputs_sender);
    free(outputs_receiver);
    free(msk_cache);
    free(csk_cache);
    free(msk);
    free(csk);
    free(inputs);

    return time_taken;
}

int main(int argc, char **argv)
{
    int testTrials = 10;
    double avg = 0;
    printf("******************************************\n");
#ifdef AVX
    printf("Benchmarking OT Generation (with AVX512)\n");
#else
    printf("Benchmarking OT Generation\n");
#endif
    for (int i = 0; i < testTrials; i++)
        avg += benchmarkOTs();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time: %f\n", avg / testTrials);
    printf("******************************************\n\n");
}