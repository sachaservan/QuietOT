#ifndef _GOLDREICH
#define _GOLDREICH

#include <stdint.h>
#include <openssl/evp.h>
#include "polymur.h"

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

typedef struct
{
    uint128_t *key_xor_128;
    uint64_t *key_xor_64;
    uint8_t *key_maj;

    // Optional fields (only present for MSK)
    uint8_t *maj_corrections;
    uint128_t xor_delta_128;
    uint64_t xor_delta_64;
    uint8_t *maj_delta;
} Key;

typedef struct
{
    size_t key_len;
    EVP_CIPHER_CTX *hash_ctx0;
    EVP_CIPHER_CTX *hash_ctx1;
    EVP_CIPHER_CTX *hash_ctx2;
    EVP_CIPHER_CTX *prg_ctx;
    PolymurHashParams polymur_params0;
    PolymurHashParams polymur_params1;
} PublicParams;

void pp_gen(PublicParams *pp);
void pp_free(PublicParams *pp);

void key_gen(
    const PublicParams *pp,
    Key *msk);

void constrain_key_gen(
    const PublicParams *pp,
    const Key *msk,
    Key *csk,
    const uint8_t *constraint);

void generate_random_inputs(
    const PublicParams *pp,
    uint16_t *xor_inputs,
    uint16_t *maj_inputs,
    const size_t num_ots);

void sender_eval(
    const PublicParams *pp,
    const Key *msk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint8_t *outputs,
    const size_t num_ots);

void receiver_eval(
    const PublicParams *pp,
    const Key *csk,
    const uint16_t *xor_inputs,
    const uint16_t *maj_inputs,
    uint8_t *outputs,
    const size_t num_ots);

void compute_correction_terms(
    const uint8_t *maj_delta,
    uint8_t *maj_corrections);

#endif