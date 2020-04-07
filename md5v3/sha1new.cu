#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <curand_kernel.h>
#include <device_functions.h>
#define uint8  unsigned char
#define uint32 unsigned long int
#define SHA1_BLOCK_SIZE 20

typedef struct {
	uint8 data[64];
	uint32 datalen;
	unsigned long long bitlen;
	uint32 state[5];
	uint32 k[4];
} CUDA_SHA1_CTX;


#ifndef ROTLEFT
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#endif

/*********************** FUNCTION DEFINITIONS ***********************/
__device__ __host__  __forceinline__ void cuda_sha1_transform(CUDA_SHA1_CTX* ctx, const uint8 data[])
{
	uint32 a, b, c, d, e, i, j, t, m[80];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);
	for (; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}
	for (; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

__device__ __host__ inline void cuda_sha1_init(CUDA_SHA1_CTX* ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0] = 0x5a827999;
	ctx->k[1] = 0x6ed9eba1;
	ctx->k[2] = 0x8f1bbcdc;
	ctx->k[3] = 0xca62c1d6;
}

__device__ __host__  inline void cuda_sha1_update(CUDA_SHA1_CTX* ctx, const uint8 data[], size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			cuda_sha1_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

__device__ __host__ inline void cuda_sha1_final(CUDA_SHA1_CTX* ctx, uint8 hash[])
{
	uint32 i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		cuda_sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	cuda_sha1_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and MD uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

__device__ __host__ inline void sha1new(uint8* msg, uint8 length, uint8 sha1[20]) {
	CUDA_SHA1_CTX ctx;
	cuda_sha1_init(&ctx);
	cuda_sha1_update(&ctx, msg, length);
	cuda_sha1_final(&ctx, sha1);
}
/*__global__ void kernel_sha1_hash(uint8* indata, uint32 inlen, uint8* outdata, uint32 n_batch)
{
	uint32 thread = blockIdx.x * blockDim.x + threadIdx.x;
	if (thread >= n_batch)
	{
		return;
	}
	uint8* in = indata + thread * inlen;
	uint8* out = outdata + thread * SHA1_BLOCK_SIZE;
	CUDA_SHA1_CTX ctx;
	cuda_sha1_init(&ctx);
	cuda_sha1_update(&ctx, in, inlen);
	cuda_sha1_final(&ctx, out);
}

extern "C"
{
	void mcm_cuda_sha1_hash_batch(uint8* in, uint32 inlen, uint8* out, uint32 n_batch)
	{
		uint8* cuda_indata;
		uint8* cuda_outdata;
		cudaMalloc(&cuda_indata, inlen * n_batch);
		cudaMalloc(&cuda_outdata, SHA1_BLOCK_SIZE * n_batch);
		cudaMemcpy(cuda_indata, in, inlen * n_batch, cudaMemcpyHostToDevice);

		uint8 thread = 256;
		uint8 block = (n_batch + thread - 1) / thread;

		kernel_sha1_hash << < block, thread >> > (cuda_indata, inlen, cuda_outdata, n_batch);
		cudaMemcpy(out, cuda_outdata, SHA1_BLOCK_SIZE * n_batch, cudaMemcpyDeviceToHost);
		cudaDeviceSynchronize();
		cudaError_t error = cudaGetLastError();
		if (error != cudaSuccess) {
			printf("Error cuda sha1 hash: %s \n", cudaGetErrorString(error));
		}
		cudaFree(cuda_indata);
		cudaFree(cuda_outdata);
	}
}
*/