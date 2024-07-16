#ifndef _PARAMS
#define _PARAMS

#define NUM_OTS 1 << 20

#define RING_DIM 128  // has to be <= 128
#define KEY_LEN 768   // needs to be divisible by CACHE_BITS
#define CACHE_BITS 16 // how many consecutive bits of the input should be cached
// TODO: remove dependency on CACHE_BITS = 16 in bipsw.c

#define POLYMUR_SEED0 0x28ce40f3881d9798ULL
#define POLYMUR_SEED1 0x67ee64638656503eULL
#define POLYMUR_TWEAK 0xdf6109d5d320a714ULL

#endif