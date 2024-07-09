#ifndef _UTILS
#define _UTILS

#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>

static inline void sample_mod_6(uint8_t *outputs, size_t num)
{
    uint8_t sample;
    size_t i = 0;
    while (i < num)
    {
        RAND_bytes(&sample, 1);
        // 252 is the largest multiple of 6 within the range of uint8_t
        if (sample < 252)
        {
            outputs[i++] = sample % 6;
        }
    }
}

static inline void sample_mod_3(uint8_t *outputs, size_t num)
{
    uint8_t sample;
    size_t i = 0;
    while (i < num)
    {
        RAND_bytes(&sample, 1);
        // 252 is the largest multiple of 3 within the range of uint8_t
        if (sample < 252)
            outputs[i++] = sample % 3;
    }
}

static inline void inplace_mod_3_addr(uint128_t *a, const uint128_t *b)
{
    static uint128_t tmp_h, tmp_l;

    // do bit-sliced mod 3 addition
    // see appendix B.1 of
    // https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/wave-spec-web.pdf
    tmp_h = (a[1] ^ b[0]) & (a[0] ^ b[1]);
    tmp_l = (a[1] ^ b[1]) | (a[0] ^ b[1] ^ b[0]);
    a[0] = tmp_h;
    a[1] = tmp_l;
}

static inline void inplace_mod_3_subr(uint128_t *a, const uint128_t *b)
{
    static uint128_t tmp_h, tmp_l;

    // do bit-sliced mod 3 subtraction
    // see appendix B.1 of
    // https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/wave-spec-web.pdf
    tmp_h = (a[1] ^ b[1] ^ b[0]) & (a[0] ^ b[1]);
    tmp_l = (a[1] ^ b[1]) | (a[0] ^ b[0]);
    a[0] = tmp_h;
    a[1] = tmp_l;
}

static inline void print_binary(uint128_t number)
{
    for (int i = 63; i >= 0; i--)
    {
        uint128_t mask = (uint128_t)1 << i;
        putchar((number & mask) ? '1' : '0');
    }
    printf("\n");
}

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
