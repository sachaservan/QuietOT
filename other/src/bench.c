#include "prf.h"
#include "prg.h"
#include "other.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#define NUM_OTS 1ULL << 15

// This benchmark emulates the sender computation based on the parameters
// provided in the BCMPR paper (section 2.6; https://eprint.iacr.org/2024/178.pdf).
double benchmark_BCMPR_GAR()
{
    OpenSSL_add_all_algorithms();

    size_t key_len = 74; // the size of the majority predicate chosen in BCMPR

    struct Params *pp = (struct Params *)malloc(sizeof(struct Params));
    setup(pp, key_len);

    // For benchmarking purposes, we generate two CPRF keys
    // one for the "MAJ" component and one for the "XOR" component
    struct Key *msk0 = (struct Key *)malloc(sizeof(struct Key));
    struct Key *msk1 = (struct Key *)malloc(sizeof(struct Key));
    key_gen(pp, msk0);
    key_gen(pp, msk1);

    // Generate hash key (for random oracle)
    uint128_t hash_key;
    RAND_bytes((uint8_t *)&hash_key, sizeof(uint128_t));
    EVP_CIPHER_CTX *hash_ctx = prf_key_gen((uint8_t *)&hash_key);

    BIGNUM *result0 = BN_new();
    BIGNUM *result1 = BN_new();

    // initialize to one
    BN_set_word(result0, 1);
    BN_set_word(result1, 1);

    EC_POINT *out = EC_POINT_new(pp->curve);

    size_t point_size = BN_num_bytes(result0);

    // assume that curve point can be represented in = 256 bits
    uint8_t *output0 = malloc(sizeof(uint8_t) * point_size * NUM_OTS);
    uint8_t *output1 = malloc(sizeof(uint8_t) * point_size * NUM_OTS);

    // get byte size of curve point
    size_t point_len = get_curve_point_byte_size(pp);
    size_t point_len_blocks = (point_len / 16); // how many fit in uint128_t
    uint8_t *point_bytes = (uint8_t *)malloc(point_len);

    uint128_t *prf_inputs_0 = malloc(sizeof(uint128_t) * point_len_blocks * NUM_OTS);
    uint128_t *prf_inputs_1 = malloc(sizeof(uint128_t) * point_len_blocks * NUM_OTS);

    clock_t t = clock();

    for (size_t n = 0; n < NUM_OTS; n++)
    {
        // Need to compute s_0 and s_1 as the sender, which translates to
        // key_len * 2 multiplications over Z_p^* and one exponentiation
        // to evaluate the PRF. We then need to "hash" the result
        // which is done using fixed-key AES
        for (size_t i = 0; i < key_len; i++)
        {
            BN_mod_mul(result0, result0, msk0->key[i], pp->order, pp->ctx);
            BN_mod_mul(result1, result1, msk1->key[i], pp->order, pp->ctx);
        }

        EC_POINT_mul(
            pp->curve,
            out,
            result0,
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
        memcpy(&prf_inputs_0[point_len_blocks * n], &point_bytes[1], point_len - 1);

        EC_POINT_mul(
            pp->curve,
            out,
            result1,
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
        memcpy(&prf_inputs_1[point_len_blocks * n], &point_bytes[1], point_len - 1);
    }

    size_t num_output_blocks = point_len_blocks * NUM_OTS;
    prf_batch_eval(hash_ctx, (uint128_t *)&prf_inputs_0[0], (uint128_t *)&output0[0], num_output_blocks);
    prf_batch_eval(hash_ctx, (uint128_t *)&prf_inputs_1[0], (uint128_t *)&output1[0], num_output_blocks);

    t = clock() - t;

    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms
    printf("Time (total) %f ms\n", time_taken);

    free_master_key(pp, msk0);
    free_master_key(pp, msk1);
    free_public_params(pp);

    return time_taken;
}

// This benchmark emulates the sender computation based on the parameters
// provided in the OSY paper (Construction 5.6: https://eprint.iacr.org/2021/262.pdf).
double benchmark_OSY()
{
    BN_CTX *ctx = BN_CTX_new();

    double time_taken = 0;
    int num_trials_internal = 3;

    for (int trial = 0; trial < num_trials_internal; trial++)
    {
        // N ~ 3200 bits for security
        BIGNUM *prime0 = BN_new();
        BIGNUM *prime1 = BN_new();
        BN_generate_prime_ex(prime0, 1600, 0, NULL, NULL, NULL);
        BN_generate_prime_ex(prime1, 1600, 0, NULL, NULL, NULL);

        BIGNUM *modulus = BN_new();
        BN_mul(modulus, prime0, prime1, ctx);
        BN_free(prime0);
        BN_free(prime1);

        BIGNUM **base = malloc(sizeof(void *) * 128);
        BIGNUM **exps = malloc(sizeof(void *) * 128);
        for (int i = 0; i < 128; i++)
        {
            base[i] = BN_new();
            exps[i] = BN_new();

            BN_rand_range(base[i], modulus);
            BN_rand_range(exps[i], modulus);
        }

        clock_t t = clock();
        for (int i = 0; i < 128; i++)
            BN_mod_exp(base[i], base[i], exps[i], modulus, ctx);

        t = clock() - t;
        time_taken += ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        for (int i = 0; i < 128; i++)
        {
            BN_free(base[i]);
            BN_free(exps[i]);
        }

        BN_free(modulus);
        free(base);
        free(exps);
    }

    printf("Time (total) %f ms\n", time_taken / num_trials_internal);

    // free up memory
    BN_CTX_free(ctx);

    return time_taken / num_trials_internal;
}

int main(int argc, char **argv)
{
    int testTrials = 10;
    double avg = 0;
    printf("******************************************\n");
    printf("Benchmarking BCMPR with GAR\n");
    for (int i = 0; i < testTrials; i++)
        avg += benchmark_BCMPR_GAR();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time: %f\n", avg / testTrials);
    printf("******************************************\n\n");

    avg = 0;
    printf("******************************************\n");
    printf("Benchmarking OSY\n");
    for (int i = 0; i < testTrials; i++)
        avg += benchmark_OSY();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time: %f\n", avg / testTrials);
    printf("******************************************\n\n");
}