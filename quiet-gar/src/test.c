#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/rand.h>

#include "prf.h"
#include "prg.h"
#include "gar.h"
#include "utils.h"

double benchmarkOTs()
{
    size_t num_ots = NUM_OTS;

    // **********************************
    // Generate public parameters
    // **********************************
    PublicParams *pp = malloc(sizeof(PublicParams));
    pp_gen(pp);

    // **********************************
    // Generate CPRF master key
    // **********************************
    Key *msk = malloc(sizeof(Key));
    key_gen(pp, msk);

    uint8_t *constraint = malloc(sizeof(uint8_t) * KEY_LEN);
    RAND_bytes((uint8_t *)constraint, sizeof(uint8_t) * KEY_LEN);
    for (size_t i = 0; i < KEY_LEN; i++)
        constraint[i] &= 1;

    // Compute the constrained key
    Key *csk = malloc(sizeof(Key));
    constrain_key_gen(pp, msk, csk, constraint);

    clock_t t = clock();

    uint16_t *xor_inputs = malloc(sizeof(uint16_t) * XOR_LEN * num_ots);
    uint16_t *maj_inputs = malloc(sizeof(uint16_t) * MAJ_LEN * num_ots);
    generate_random_inputs(pp, xor_inputs, maj_inputs, num_ots);

    uint8_t *outputs_sender = malloc(sizeof(uint8_t) * num_ots * NUM_COMBOS);
    uint8_t *outputs_receiver = malloc(sizeof(uint8_t) * num_ots);

    sender_eval(pp,
                msk,
                xor_inputs,
                maj_inputs,
                outputs_sender,
                num_ots);

    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("Took %.2f ms to generate %zu OTs\n", time_taken, num_ots);

    receiver_eval(pp,
                  csk,
                  xor_inputs,
                  maj_inputs,
                  outputs_receiver,
                  num_ots);

    // **********************************
    // Test correctness and generate stats
    // **********************************

    // TEST 1: make sure all input values are < KEY_LEN
    for (size_t n = 0; n < num_ots; n++)
    {
        uint16_t *xor_input = &xor_inputs[n * XOR_LEN];
        uint16_t *maj_input = &maj_inputs[n * MAJ_LEN];

        for (size_t i = 0; i < XOR_LEN; i++)
        {
            if (xor_input[i] > KEY_LEN)
            {
                printf("FAIL: XOR input index out of bounds\n");
                exit(0);
            }
        }

        for (size_t i = 0; i < MAJ_LEN; i++)
        {
            if (maj_input[i] > KEY_LEN)
            {
                printf("FAIL: MAJ input index out of bounds\n");
                exit(0);
            }
        }
    }

    int dist[NUM_COMBOS] = {0};     // output index distribution
    double not_found = 0;           // number of failures (no matching value found)
    int err_hist[NUM_COMBOS] = {0}; // histogram of where errors ocurred

    for (size_t n = 0; n < num_ots; n++)
    {
        // compute weak PRF output (inner product between input and constraint)
        uint16_t *xor_input = &xor_inputs[n * XOR_LEN];
        uint16_t *maj_input = &maj_inputs[n * MAJ_LEN];

        uint8_t idx = 0;
        uint8_t xor = 0;
        uint8_t maj = 0;
        for (size_t i = 0; i < XOR_LEN; i++)
            xor += constraint[xor_input[i]];

        for (size_t i = 0; i < MAJ_LEN; i++)
            maj += constraint[maj_input[i]];

        idx = (xor% 2) * (MAJ_LEN + 1) + maj;

        dist[idx]++; // keep a count of all seen indices

        int found = 0;
        for (size_t j = 0; j < NUM_COMBOS; j++)
        {
            if (outputs_sender[n * NUM_COMBOS + j] == outputs_receiver[n])
                found = j;
        }

        if (outputs_sender[n * NUM_COMBOS + idx] != outputs_receiver[n])
            not_found++;
        else
            found = idx;

        if (idx != found)
            err_hist[found]++;
    }

    // printf("Index dist: (");
    // for (size_t i = 0; i < NUM_COMBOS; i++)
    //     printf("%i ", dist[i]);
    // printf(")\n");

    if (not_found != 0)
    {
        printf("ERROR: %f fraction of values not found!\n", not_found / (double)num_ots);
        printf("Error hist: (");
        for (size_t i = 0; i < NUM_COMBOS; i++)
        {
            printf("%i ", err_hist[i]);
        }
        printf(")\n");
        printf("FAIL\n\n");
    }
    else
    {
        printf("PASS\n\n");
    }

    pp_free(pp);
    free(constraint);
    free(outputs_sender);
    free(outputs_receiver);
    free(msk);
    free(csk);
    free(xor_inputs);
    free(maj_inputs);

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
    avg = avg / testTrials;
    printf("******************************************\n");
    printf("SUMMARY\n");
    printf("Avg. time: %.2f ms to generate %llu OTs\n", avg, (long long unsigned int)NUM_OTS);
    printf("Performance: %.2f OTs/sec\n", ((double)(NUM_OTS) / avg) * 1000); // Convert ms to seconds
    printf("Number of trials: %i\n", testTrials);
    printf("******************************************\n\n");
}