
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <curand_kernel.h>
#include <device_functions.h>
__constant__ uint32_t expo_d[4] = { 1, 256, 65536, 16777216 };

__device__ __host__ inline uint32_t f_CUDA(uint32_t B, uint32_t C, uint32_t D, int t)
{
    if (t < 20)
    {
        return ((B & C) ^ (~B & D));
    }
    if ((t > 19)& (t < 40))
    {
        return (B ^ C ^ D);
    }
    if ((t > 39)& (t < 60))
    {
        return ((B & C) ^ (B & D) ^ (C & D));
    }
    if (t > 59)
    {
        return (B ^ C ^ D);
    }
    return B;
}

__device__ __host__ inline uint32_t Rol_CUDA(uint32_t x, int y)
{
    if (y % 32 == 0) { return x; }
    else { return ((x << y) ^ (x >> -y)); }
}

//SHA1-Function
__device__ __host__ void SHA1(unsigned char* s, int slen, uint32_t *h0, uint32_t* h1, uint32_t* h2, uint32_t* h3, uint32_t* h4)
{
    uint32_t H[5];
    uint32_t K[80];
    uint32_t A, B, C, D, E, TEMP;
    int r, k, ln, t, l, i, j;

    H[0] = 0x67452301;
    H[1] = 0xefcdab89;
    H[2] = 0x98badcfe;
    H[3] = 0x10325476;
    H[4] = 0xc3d2e1f0;

    ln = slen;
    r = (int)((ln + 1) / 64);

    if (((ln + 1) % 64) > 56)
    {
        r = r + 1;
    }

    // initialize Constants
    //pragma unroll
    for (t = 0; t < 80; t++)
    {
        if (t < 20)
        {
            K[t] = 0x5a827999;
        }

        if ((t > 19)& (t < 40))
        {
            K[t] = 0x6ED9EBA1;
        }
        if ((t > 39)& (t < 60))
        {
            K[t] = 0x8F1BBCDC;
        }
        if (t > 59)
        {
            K[t] = 0xca62c1d6;
        }
    }


    for (l = 0; l <= r; l++)
    {
        uint32_t W[80] = { 0 };
        //Initialize Text

        for (i = 0; i < 16; i++)
        {
            //pragma unroll
            for (j = 0; j < 4; j++)
            {
                if (4 * i + j < ln)
                {
                    k = s[64 * l + 4 * i + j];
                }
                else
                {
                    k = 0;
                }

                if (k < 0)
                {
                    k = k + 256;
                }

                if (4 * i + j == ln)
                {
                    k = 0x80;
                }

                //                              W[i]= W[i] + k*(uint32_t)pow(256,(double)3-j);
                W[i] = W[i] + k * expo_d[3 - j];
            }
        }
        if ((W[14] == 0) & (W[15] == 0))
        {
            W[15] = 8 * slen;
        }

        // Hash Cycle


        for (t = 16; t < 80; t++)
        {
            W[t] = Rol_CUDA(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
        }

        A = H[0];
        B = H[1];
        C = H[2];
        D = H[3];
        E = H[4];

        for (t = 0; t < 80; t++)
        {
            TEMP = (Rol_CUDA(A, 5) + f_CUDA(B, C, D, t) + E + W[t] + K[t]);
            E = D;
            D = C;
            C = Rol_CUDA(B, 30);
            B = A;
            A = TEMP;
        }

        H[0] = H[0] + A;
        H[1] = H[1] + B;
        H[2] = H[2] + C;
        H[3] = H[3] + D;
        H[4] = H[4] + E;

        ln = ln - 64;
    }
    h0 = &H[0];
    h1 = &H[1];
    h2 = &H[3];
    h3 = &H[3];
    h4 = &H[4];

}