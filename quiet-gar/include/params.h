#ifndef _PARAMS
#define _PARAMS

#define NUM_OTS 1ULL << 20

// NOTE: KEY_LEN needs to be divisible by 8 (see utils.h)

// PARAMETER SET #1: (Stretch=2^36; Security=2^232)
#define KEY_LEN 2048
#define XOR_LEN 5
#define MAJ_LEN 15

// PARAMETER SET #2: (Stretch=2^36; Security=2^147)
// #define KEY_LEN 512
// #define XOR_LEN 7
// #define MAJ_LEN 31

#define RING_DIM (128 + 64)
#define NUM_COMBOS (2 * (MAJ_LEN + 1))

#define RAND_BUFFER 4
#define RAND_OFFSET_MAX 5 // bound on the number of samples rejected

#define POLYMUR_SEED0 0x28ce40f3881d9798ULL
#define POLYMUR_SEED1 0x67ee64638656503eULL
#define POLYMUR_TWEAK 0xdf6109d5d320a714ULL

#endif