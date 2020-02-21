#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <curand_kernel.h>
#include <device_functions.h>
#define rotateleft(x,n) ((x<<n) | (x>>(32-n)))
#define rotateright(x,n) ((x>>n) | (x<<(32-n)))
__device__ __host__ inline void sha1(unsigned char* _word, uint32_t length, uint32_t* hash0, uint32_t* hash1, uint32_t* hash2, uint32_t* hash3, uint32_t* hash4)
{
    unsigned char* _word_ = _word;
    uint32_t h0, h1, h2, h3, h4, a, b, c, d, e, f, k, temp;
    h0 = 0x67452301;
    h1 = 0xEFCDAB89;
    h2 = 0x98BADCFE;
    h3 = 0x10325476;
    h4 = 0xC3D2E1F0;
    int i, current_length = length, original_length = length;
    _word_[current_length] = 0x80;
    _word_[current_length + 1] = '\0';
    current_length++;
    int ib = current_length % 64;
    if (ib < 56)
        ib = 56 - ib;
    else
        ib = 120 - ib;
    for (int i = 0; i < ib; i++)
    {
        _word_[current_length] = 0x00;
        current_length++;
    }
    _word_[current_length + 1] = '\0';
    for (i = 0; i < 6; i++)
    {
        _word_[current_length] = 0x0;
        current_length++;
    }
    _word_[current_length] = (original_length * 8) / 0x100;
    current_length++;
    _word_[current_length] = (original_length * 8) % 0x100;
    current_length++;
    _word_[current_length + i] = '\0';
    int number_of_chunks = current_length / 64;
    unsigned long int word[80];
    for (i = 0; i < number_of_chunks; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            word[j] = _word_[i * 64 + j * 4 + 0] * 0x1000000 + _word_[i * 64 + j * 4 + 1] * 0x10000 + _word_[i * 64 + j * 4 + 2] * 0x100 + _word_[i * 64 + j * 4 + 3];
        }
        for (int j = 16; j < 80; j++)
        {
            word[j] = rotateleft((word[j - 3] ^ word[j - 8] ^ word[j - 14] ^ word[j - 16]), 1);
        }
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        for (int m = 0; m < 80; m++)
        {
            if (m <= 19)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (m <= 39)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (m <= 59)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            temp = (rotateleft(a, 5) + f + e + k + word[m]) & 0xFFFFFFFF;
            e = d;
            d = c;
            c = rotateleft(b, 30);
            b = a;
            a = temp;
        }
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
    }

    *hash0 = h0;
    *hash1 = h1;
    *hash2 = h2;
    *hash3 = h3;
    *hash4 = h4;
}