#ifndef _GOLDREICH
#define _GOLDREICH

#include <stdint.h>
#include <openssl/evp.h>
#include "polymur.h"

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

struct Key
{
    uint128_t *key_xor;
    uint8_t *key_maj;

    // optional fields (only present for MSK)
    uint8_t *maj_corrections;
    uint128_t xor_delta;
    uint8_t *maj_delta;
};

struct PublicParams
{
    size_t key_len;
    EVP_CIPHER_CTX *hash_ctx;
    EVP_CIPHER_CTX *prg_ctx;
    PolymurHashParams polymur_params0;
    PolymurHashParams polymur_params1;
};

void pp_gen(struct PublicParams *pp);
void pp_free(struct PublicParams *pp);

void key_gen(struct PublicParams *pp, struct Key *msk);

void constrain_key_gen(
    struct PublicParams *pp,
    struct Key *msk,
    struct Key *csk,
    uint8_t *constraint);

void GenerateRandomInputs(
    struct PublicParams *pp,
    uint16_t *xor_inputs,
    uint16_t *maj_inputs,
    size_t num_ots);

void sender_eval(
    struct PublicParams *pp,
    struct Key *msk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint128_t *outputs,
    const size_t num_ots);

void receiver_eval(
    struct PublicParams *pp,
    struct Key *csk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint128_t *outputs,
    const size_t num_ots);

void compute_correction_terms(
    uint8_t *maj_delta,
    uint8_t *maj_corrections);

#endif