#ifndef _PARAMS
#define _PARAMS

#define NUM_OTS 1 << 20

#define RING_DIM 128  // has to be <= 128
#define KEY_LEN 768   // needs to be divisible by CACHE_BITS
#define CACHE_BITS 16 // how many consecutive bits of the input should be cached

#define UHASH_PRIME "7fffffffffffffffffffffffffffff61"

#endif