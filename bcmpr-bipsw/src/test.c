#include "bcmpr.h"
#include "prf.h"
#include "prg.h"
#include "params.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

double benchmarkOTs()
{
    OpenSSL_add_all_algorithms();

    size_t num_ots = NUM_OTS;
    size_t key_len = KEY_LEN;

    // **********************************
    // Generate PRG key (for generating random inputs)
    // Generate hash key (for random oracle)
    // **********************************
    uint128_t prg_key;
    RAND_bytes((uint8_t *)&prg_key, sizeof(uint128_t));
    EVP_CIPHER_CTX *prg_ctx = PRGkey_gen((uint8_t *)&prg_key);

    // **********************************
    // Generate public parameters
    // **********************************
    Params *pp = (Params *)malloc(sizeof(Params));
    setup(pp, key_len);

    // **********************************
    // Generate CPRF keys
    // **********************************
    Key *msk0 = (Key *)malloc(sizeof(Key));
    Key *msk1 = (Key *)malloc(sizeof(Key));
    if (!key_gen(pp, msk0))
        printf("ERROR: when generating msk0\n");
    if (!key_gen(pp, msk1))
        printf("ERROR: when generating msk1\n");

    // **********************************
    // Generate constrained CPRF keys
    // **********************************
    uint8_t *constraint = malloc(sizeof(uint8_t) * key_len);
    RAND_bytes((uint8_t *)constraint, sizeof(uint8_t) * key_len);
    for (size_t i = 0; i < key_len; i++)
        constraint[i] &= 1;

    Key *csk0 = (Key *)malloc(sizeof(Key));
    Key *csk1 = (Key *)malloc(sizeof(Key));
    constrain_key_gen(pp, msk0, csk0, constraint, 0);
    constrain_key_gen(pp, msk1, csk1, constraint, 1);

    // **********************************
    // Compute caches
    // **********************************
    KeyCache *msk0_cache = (KeyCache *)malloc(sizeof(KeyCache));
    KeyCache *msk1_cache = (KeyCache *)malloc(sizeof(KeyCache));
    if (!compute_cache(pp, msk0->key, msk0_cache, CACHE_BITS))
        printf("Error ocurred when computing cache with msk0\n");

    if (!compute_cache(pp, msk1->key, msk1_cache, CACHE_BITS))
        printf("Error ocurred when computing cache with msk1\n");

    KeyCache *csk0_cache = (KeyCache *)malloc(sizeof(KeyCache));
    KeyCache *csk1_cache = (KeyCache *)malloc(sizeof(KeyCache));
    compute_cache(pp, csk0->key, csk0_cache, CACHE_BITS);
    compute_cache(pp, csk1->key, csk1_cache, CACHE_BITS);

    // **********************************
    // Evaluate CPRF
    // **********************************

    // get byte size of curve point
    size_t point_len = get_curve_point_byte_size(pp);
    size_t point_len_blocks = (point_len / 16); // how many fit in uint128_t
    uint128_t *outputs_sender_0 = calloc(num_ots * point_len_blocks, sizeof(uint128_t));
    uint128_t *outputs_sender_1 = calloc(num_ots * point_len_blocks, sizeof(uint128_t));
    uint128_t *outputs_receiver = calloc(num_ots * point_len_blocks, sizeof(uint128_t));

    size_t packed = ceil((pp->key_len) / 128);
    uint128_t *seed = calloc(num_ots * packed, sizeof(uint128_t));
    uint128_t *inputs = malloc(sizeof(uint128_t) * num_ots * packed);
    prg_eval(prg_ctx, (uint128_t *)seed, (uint128_t *)inputs, num_ots * packed);

    clock_t t = clock();

    if (!sender_eval(pp, msk0_cache, inputs, outputs_sender_0, num_ots))
        printf("Error ocurred during eval with msk0\n");

    if (!sender_eval(pp, msk1_cache, inputs, outputs_sender_1, num_ots))
        printf("Error ocurred during eval with msk1\n");

    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("Took %.2f ms to generate %zu OTs\n", time_taken, num_ots);

    if (!receiver_eval(
            pp,
            csk0,
            csk1,
            csk0_cache,
            csk1_cache,
            constraint,
            inputs,
            outputs_receiver,
            num_ots))
        printf("Error ocurred during eval with csk\n");

    for (size_t n = 0; n < num_ots * point_len_blocks; n++)
    {
        int exists0 = (outputs_receiver[n] == outputs_sender_0[n]);
        int exists1 = (outputs_receiver[n] == outputs_sender_1[n]);

        if (!exists0 && !exists1)
        {
            printf("ERROR: %zu-th correlation is invalid\n", n);
            printf("FAIL\n\n");
            exit(0);
        }
    }

    printf("PASS\n\n");

    free(inputs);
    free(outputs_sender_0);
    free(outputs_sender_1);
    free(outputs_receiver);

    free_master_key(pp, msk0);
    free_master_key(pp, msk1);
    free_constrained_key(pp, csk0);
    free_constrained_key(pp, csk1);
    free_cache(pp, msk0_cache);
    free_cache(pp, msk1_cache);
    free_public_params(pp);

    return time_taken;
}

int main(int argc, char **argv)
{
    int testTrials = 10;
    double avg = 0;
    printf("******************************************\n");
    printf("Benchmarking OT Generation\n");
    for (int i = 0; i < testTrials; i++)
        avg += benchmarkOTs();
    printf("******************************************\n");
    avg = avg / testTrials;
    printf("SUMMARY\n");
    printf("Avg. time: %.2f ms to generate %llu OTs\n", avg, (long long unsigned int)NUM_OTS);
    printf("Performance: %i OTs/sec\n", (int)(((double)(NUM_OTS) / avg) * 1000)); // Convert ms to seconds
    printf("Number of trials: %i\n", testTrials);
    printf("******************************************\n\n");
}