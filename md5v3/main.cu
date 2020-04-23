#include <string.h>
#include <stdio.h>
#include <iostream>
//#include <time.h>
//#include <string.h>
//#include <windows.h>
//#include <wincrypt.h> /* CryptAcquireContext, CryptGenRandom */
#include <cuda_runtime.h>
//#include <cuda_runtime_api.h>
//#include <curand_kernel.h>
#include <device_functions.h>
#include "device_launch_parameters.h"

#define uint8  unsigned char

#define CONST_WORD_LIMIT 10
#define CONST_CHARSET_LIMIT 100

#define CONST_CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CONST_CHARSET_LENGTH (sizeof(CONST_CHARSET) - 1)

#define CONST_WORD_LENGTH_MIN 1
#define CONST_WORD_LENGTH_MAX 8

//#define BCRYPT_HASHSIZE 60
//#define RANDBYTES (16)

#include "assert.cu"
#include "md5.cu"
#include "sha1.cu"
#include "sha256.cu"
#include "keccak.cu"
#include "sha1new.cu"
#include "md5new.cu"
#include "keccakv2.cu"
 /* Global variables */
uint8_t g_wordLength;

char g_word[CONST_WORD_LIMIT];
char g_charset[CONST_CHARSET_LIMIT];
char g_cracked[CONST_WORD_LIMIT];
int BLOCKS, THREADS, devices;

__device__ char g_deviceCharset[CONST_CHARSET_LIMIT], g_deviceCracked[CONST_WORD_LIMIT];

__device__ __host__ bool next(uint8_t* length, char* word, uint32_t increment) {
    uint32_t idx = 0;
    uint32_t add = 0;

    while (increment > 0 && idx < CONST_WORD_LIMIT) {
        if (idx >= *length && increment > 0) {
            increment--;
        }

        add = increment + word[idx];
        word[idx] = add % CONST_CHARSET_LENGTH;
        increment = add / CONST_CHARSET_LENGTH;
        idx++;
    }

    if (idx > * length) {
        *length = idx;
    }

    if (idx > CONST_WORD_LENGTH_MAX) {
        return false;
    }

    return true;
}

__device__ __host__ bool compare(uint8 a[], uint8 b[], int len)
{
    for (int i = 0; i < len; i++)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

__global__ void md5Crack(uint8_t wordLength, char* charsetWord, uint32_t hash01, uint32_t hash02, uint32_t hash03, uint32_t hash04) {
    uint32_t idx = (blockIdx.x * blockDim.x + threadIdx.x);
    __shared__ char sharedCharset[CONST_CHARSET_LIMIT];
    char threadCharsetWord[CONST_WORD_LIMIT];
    char threadTextWord[CONST_WORD_LIMIT];
    uint8_t threadWordLength;
    uint32_t threadHash01, threadHash02, threadHash03, threadHash04;
    memcpy(threadCharsetWord, charsetWord, CONST_WORD_LIMIT);
    memcpy(&threadWordLength, &wordLength, sizeof(uint8_t));
    memcpy(sharedCharset, g_deviceCharset, sizeof(uint8_t) * CONST_CHARSET_LIMIT);
    next(&threadWordLength, threadCharsetWord, idx);

    for (uint32_t i = 0; i < threadWordLength; i++) {
        threadTextWord[i] = sharedCharset[threadCharsetWord[i]];
    }

    md5Hash((unsigned char*)threadTextWord, threadWordLength, &threadHash01, &threadHash02, &threadHash03, &threadHash04);

    if (threadHash01 == hash01 && threadHash02 == hash02 && threadHash03 == hash03 && threadHash04 == hash04) {
        memcpy(g_deviceCracked, threadTextWord, threadWordLength);
    }

    if (!next(&threadWordLength, threadCharsetWord, 1)) {
        return;
    }
}
__global__ void md5Crack2(uint8_t wordLength, char* charsetWord, uint8* origin) {
    uint32_t idx = (blockIdx.x * blockDim.x + threadIdx.x);
    __shared__ char sharedCharset[CONST_CHARSET_LIMIT];
    char threadCharsetWord[CONST_WORD_LIMIT];
    uint8 threadTextWord[CONST_WORD_LIMIT], md5sum[16];
    uint8_t threadWordLength;
    
    memcpy(threadCharsetWord, charsetWord, CONST_WORD_LIMIT);
    memcpy(&threadWordLength, &wordLength, sizeof(uint8_t));
    memcpy(sharedCharset, g_deviceCharset, sizeof(uint8_t) * CONST_CHARSET_LIMIT);
    next(&threadWordLength, threadCharsetWord, idx);

    for (uint32_t i = 0; i < threadWordLength; i++) {
        threadTextWord[i] = sharedCharset[threadCharsetWord[i]];
    }

    md5new(threadTextWord, +wordLength, md5sum);
    if (compare(md5sum, origin, 16)) {
        memcpy(g_deviceCracked, threadTextWord, wordLength);
    }
    if (!next(&threadWordLength, threadCharsetWord, 1)) {
        return;
    }
}
__global__ void sha1Crack(uint8_t wordLength, char* charsetWord, uint32_t hash01, uint32_t hash02, uint32_t hash03, uint32_t hash04, uint32_t hash05) {
    uint32_t idx = (blockIdx.x * blockDim.x + threadIdx.x);
    __shared__ char sharedCharset[CONST_CHARSET_LIMIT];
    char threadCharsetWord[CONST_WORD_LIMIT], threadTextWord[CONST_WORD_LIMIT];
    uint8_t threadWordLength;
    uint32_t threadHash01, threadHash02, threadHash03, threadHash04, threadHash05;
    memcpy(threadCharsetWord, charsetWord, CONST_WORD_LIMIT);
    memcpy(&threadWordLength, &wordLength, sizeof(uint8_t));
    memcpy(sharedCharset, g_deviceCharset, sizeof(uint8_t) * CONST_CHARSET_LIMIT);
    next(&threadWordLength, threadCharsetWord, idx);
    for (uint32_t i = 0; i < wordLength; i++) {
        threadTextWord[i] = sharedCharset[threadCharsetWord[i]];
    }

    sha1((unsigned char*)threadTextWord, wordLength, &threadHash01, &threadHash02, &threadHash03, &threadHash04, &threadHash05);
    if (threadHash01 == hash01 && threadHash02 == hash02 && threadHash03 == hash03 && threadHash04 == hash04 && threadHash05 == hash05) {
        memcpy(g_deviceCracked, threadTextWord, wordLength);
    }

    if (!next(&threadWordLength, threadCharsetWord, 1)) {
        return;
    }
}

__global__ void sha1Crack2(uint8_t wordLength, char* charsetWord, uint8* origin) {
    uint32_t idx = (blockIdx.x * blockDim.x + threadIdx.x);
    __shared__ char sharedCharset[CONST_CHARSET_LIMIT];
    char threadCharsetWord[CONST_WORD_LIMIT];
    uint8 threadTextWord[CONST_WORD_LIMIT], sha1sum[21];
    uint8_t threadWordLength;

    memcpy(threadCharsetWord, charsetWord, CONST_WORD_LIMIT);
    memcpy(&threadWordLength, &wordLength, sizeof(uint8_t));
    memcpy(sharedCharset, g_deviceCharset, sizeof(uint8_t) * CONST_CHARSET_LIMIT);
    next(&threadWordLength, threadCharsetWord, idx);
    for (uint32_t i = 0; i < wordLength; i++) {
        threadTextWord[i] = sharedCharset[threadCharsetWord[i]];
    }

    //sha1((unsigned char*)threadTextWord, wordLength, &threadHash01, &threadHash02, &threadHash03, &threadHash04, &threadHash05);
    sha1new(threadTextWord, +wordLength, sha1sum);
    if (compare(sha1sum,origin,20)) {
        memcpy(g_deviceCracked, threadTextWord, wordLength);
    }

    if (!next(&threadWordLength, threadCharsetWord, 1)) {
        return;
    }
}


__global__ void sha256Crack(uint8_t wordLength, char* charsetWord, uint8* unhexed) {
    uint32_t idx = (blockIdx.x * blockDim.x + threadIdx.x);
    __shared__ char sharedCharset[CONST_CHARSET_LIMIT];
    char threadCharsetWord[CONST_WORD_LIMIT];
    uint8 threadTextWord[CONST_WORD_LIMIT], sha256sum[33];
    uint8_t threadWordLength;
    memcpy(threadCharsetWord, charsetWord, CONST_WORD_LIMIT);
    memcpy(&threadWordLength, &wordLength, sizeof(uint8_t));
    memcpy(sharedCharset, g_deviceCharset, sizeof(uint8_t) * CONST_CHARSET_LIMIT);
    next(&threadWordLength, threadCharsetWord, idx);

    for (uint32_t i = 0; i < wordLength; i++) {
        threadTextWord[i] = sharedCharset[threadCharsetWord[i]];
    }

    sha256(threadTextWord, +wordLength, sha256sum);

    if (compare(unhexed, sha256sum, 32)){
        memcpy(g_deviceCracked, threadTextWord, wordLength);
    }

    if (!next(&threadWordLength, threadCharsetWord, 1)) {
        return;
    }
}

void string_to_hex(uint8* msg, size_t msg_sz, char* hex, size_t hex_sz)
{
    memset(msg, '\0', msg_sz);
    for (int i = 0; i < hex_sz; i += 2)
    {
        uint8_t msb = (hex[i + 0] <= '9' ? hex[i + 0] - '0' : (hex[i + 0] & 0x5F) - 'A' + 10);
        uint8_t lsb = (hex[i + 1] <= '9' ? hex[i + 1] - '0' : (hex[i + 1] & 0x5F) - 'A' + 10);
        msg[i / 2] = (msb << 4) | lsb;
    }
}

int hash_length(char* hash) {
    int count = 0;

    for (int i = 0; hash[i] != '\0'; i++)
        count++;

    return count;
}

//int bcrypt_gensalt(int factor, char salt[BCRYPT_HASHSIZE])
//{
//    int fd;
//    char input[RANDBYTES];
//    int workf;
//    char* aux;
//
//    // Note: Windows does not have /dev/urandom sadly.
//#ifdef _WIN32 || _WIN64
//    HCRYPTPROV p;
//    ULONG     i;
//
//    // Acquire a crypt context for generating random bytes.
//    if (CryptAcquireContext(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
//        return 1;
//    }
//
//    if (CryptGenRandom(p, RANDBYTES, (BYTE*)input) == FALSE) {
//        return 2;
//    }
//
//    if (CryptReleaseContext(p, 0) == FALSE) {
//        return 3;
//    }
//#else
//    // Get random bytes on Unix/Linux.
//    fd = open("/dev/urandom", O_RDONLY);
//    if (fd == -1)
//        return 1;
//
//    if (try_read(fd, input, RANDBYTES) != 0) {
//        if (try_close(fd) != 0)
//            return 4;
//        return 2;
//    }
//
//    if (try_close(fd) != 0)
//        return 3;
//#endif
//
//    /* Generate salt. */
//    workf = (factor < 4 || factor > 31) ? 12 : factor;
//
//    aux = crypt_gensalt_rn("$2a$", workf, input, RANDBYTES,
//        salt, BCRYPT_HASHSIZE);
//    return (aux == NULL) ? 5 : 0;
//}

int gcd(int a, int b) {
    return (a == 0) ? b : gcd(b % a, a);
}

void gpu_init() {
    cudaDeviceProp device_prop;

    cudaGetDeviceCount(&devices);
    if (devices < 1) {
        exit(EXIT_FAILURE);
    }

    if (cudaGetDeviceProperties(&device_prop, 0) != cudaSuccess) {
        exit(EXIT_FAILURE);
    }

    int max_threads_per_mp = device_prop.maxThreadsPerMultiProcessor;
    int block_size = (max_threads_per_mp / gcd(max_threads_per_mp, device_prop.maxThreadsPerBlock));
    THREADS = max_threads_per_mp / block_size;
    BLOCKS = block_size * device_prop.multiProcessorCount;
    //int clock_speed = (int)(device_prop.memoryClockRate * 1000 * 1000);
}
static void test_blake2b_wo_key(char word[4])
{
    uint32 test_block_size[] = { 16,32,64 };
    uint32 INPUT_SIZE = 4;
    uint8* KEY = NULL;
    uint32 KEYLEN = 0;

    uint32 BLAKE2B_BLOCK_SIZE = test_block_size[1];
    // TEST BLAKE2B
    /*BYTE blake2b_inp[INPUT_SIZE*1024];
    BYTE blake2b_oup[1024*BLAKE2B_BLOCK_SIZE];*/
    uint8* blake2b_inp = (uint8*)malloc(INPUT_SIZE * 1024 * sizeof(BYTE));
    uint8* blake2b_oup = (uint8*)malloc(1024 * BLAKE2B_BLOCK_SIZE * sizeof(BYTE));
    srand(0);
    for (unsigned int i = 0; i < 1024 * INPUT_SIZE; i++)
    {
        blake2b_inp[i] = rand() % 256;
    }
    // CPU hash
    for (int i = 0; i < 1024; i++)
    {
        keccaknew((unsigned char*)word, INPUT_SIZE, blake2b_oup + BLAKE2B_BLOCK_SIZE * i, BLAKE2B_BLOCK_SIZE << 3);
    }

    //BYTE blake2b_cu_oup[1024*BLAKE2B_BLOCK_SIZE];
    BYTE* blake2b_cu_oup = (BYTE*)malloc(1024 * BLAKE2B_BLOCK_SIZE * sizeof(BYTE));
    keccaknew((unsigned char*)word, INPUT_SIZE, blake2b_cu_oup, BLAKE2B_BLOCK_SIZE << 3);

    if (memcmp(blake2b_oup, blake2b_cu_oup, BLAKE2B_BLOCK_SIZE * 1024) != 0)
    {
        printf("Failed test BLAKE2B no key, len %u \n", BLAKE2B_BLOCK_SIZE);
    }
    else
    {
        printf("Passed test BLAKE2B no key, len %u \n", BLAKE2B_BLOCK_SIZE);
    }
    free(blake2b_inp);
    free(blake2b_oup);
    free(blake2b_cu_oup);
}
char* phex(const void* p, size_t n)
{
    const unsigned char* cp = (unsigned char*) p;              /* Access as bytes. */
    char* s = (char*) malloc(2 * n + 1);       /* 2*n hex digits, plus NUL. */
    size_t k;

    /*
     * Just in case - if allocation failed.
     */
    if (s == NULL)
        return s;

    for (k = 0; k < n; ++k) {
        /*
         * Convert one byte of data into two hex-digit characters.
         */
        sprintf(s + 2 * k, "%02X", cp[k]);
    }

    /*
     * Terminate the string with a NUL character.
     */
    s[2 * n] = '\0';

    return s;
}

__device__ __host__ void makedigits(unsigned char x, unsigned char(&digits)[2])
{
    unsigned char d0 = x / 16;
    digits[1] = x - d0 * 16;
    unsigned char d1 = d0 / 16;
    digits[0] = d0 - d1 * 16;
}

__device__ __host__ void makehex(unsigned char(&digits)[2], char(&hex)[2])
{
    for (int i = 0; i < 2; ++i) {
        if (digits[i] < 10) {
            hex[i] = '0' + digits[i];
        }
        else {
            hex[i] = 'a' + (digits[i] - 10);
        }
    }
}

__device__ __host__ void hex_to_string(unsigned char* input, char* output, int size)
{

    for (int i = 0; i < 16; ++i) {
        unsigned char val = input[i];
        unsigned char d[2];
        char h[2];
        makedigits(val, d);
        makehex(d, h);
        output[2 * i] = h[0];
        output[2 * i + 1] = h[1];
    }
}

int main(int argc, char* argv[]) {
    /*char* w = new char[4];
    w[0] = 'k';
    w[1] = 'i';
    w[2] = 's';
    w[3] = 'a';
    test_blake2b_wo_key(w);*/
    char* hash;// = "e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98";
  /*  unsigned char* sha3hash = new unsigned char[64];
    char* word = "kisa";
    keccak(word, 4, sha3hash, 64);
    for (int i = 0; i < 100; ++i)
        std::cout << std::hex << (int)sha3hash[i];
    std::cout << std::endl;

    std::cout << "15: " << std::hex << 15;*/


   /*char* testhash = "775a2dae52c3ef080726dd427f81bd482fdf96b5";
   char* word = "zzzz";
   unsigned char* sha1hash = new unsigned char[41];
   sha1new((unsigned char*)word, 4, sha1hash);
   uint8 sha1Unhexed[21];
   hex_to_string(sha1Unhexed, 20, testhash, 40);
   for (int i = 0; i < 20; i++)
   {
       if (sha1Unhexed[i] != sha1hash[i])
           std::cout << "not equal" << std::endl;
   }*/
   

    char* testhash = "1c0d894f6f6ab511099a568f6e876c2f";
    char* word = "kisa";
    unsigned char* md5Hash = new unsigned char[32];
    md5new((unsigned char*)word, 4, md5Hash);
    uint8 md5unh[16];
    string_to_hex(md5unh, 16, testhash, 32);
    for (int i = 0; i < 16; i++)
    {
        if (md5unh[i] != md5Hash[i]);
            //std::cout << "not equal" << std::endl;
    }
    char str[16][2];
    char* new_word = (char*) malloc(sizeof(char)*32);
    for (int j = 0; j < 16; ++j) {
        sprintf(str[j], "%02x", md5Hash[j]);
    }
    
    for(int i = 0; i < 16; i++)
        std::cout << str[i][0] << str[i][1];

    std::cout << std::endl;

    unsigned char* d_md5Hash;
    cudaMalloc(&d_md5Hash, 32 * sizeof(unsigned char));
    cudaMemcpy(d_md5Hash, &md5Hash[0], 32 * sizeof(unsigned char),
        cudaMemcpyHostToDevice);

    char* d_str1;
    cudaMalloc(&d_str1, 32 * sizeof(char));
    char str1[32];
    //kernel<<<1,1>>>(d_md5Hash, d_str1);
    cudaMemcpy(&str1[0], d_str1, 32 * sizeof(char), cudaMemcpyDeviceToHost);
    for (int i = 0; i < 32; i += 2) std::cout << str1[i] << str1[i + 1];
    std::cout << std::endl;

    /*bool next_ = true;
    int k = 0;
    int m = 0;
    while (next_) {
        new_word[k] = str[m][0];
        new_word[k + 1] = str[m][1];
        k += 2;
        m++;
        if (k >= 32)
            next_ = false;
    }
    */
    for (int i = 0; i < 16; i++) {
        new_word[2 * i] = str[i][0];
        new_word[2 * i + 1] = str[i][1];
    }

    for (int i = 0; i < 32; i++)
        std::cout << new_word[i];
    std::cout << std::endl;
    unsigned char* md5Hash2 = new unsigned char[32];
    md5new((unsigned char*)new_word, 32, md5Hash2);
    for (int i = 0; i < 16; i++)
    {
        if (md5unh[i] != md5Hash2[i]);
        //std::cout << "not equal" << std::endl;
    }
    char str2[16][1];
    for (int j = 0; j < 16; ++j) {
        //printf("%02x", md5Hashh[j]);
        sprintf(str2[j], "%02x", md5Hash2[j]);
        std::cout << str2[j];
    }
   /* Check arguments */
   if (argc != 2) {
        std::cout << "Need hash password. Now arguments count: " << argc << std::endl;
            return -1;
    }
    else {
        hash = argv[1];
        std::cout << "Set hash [" << hash << "]" << std::endl;
    }

    int hash_size = hash_length(hash);
    gpu_init();
    cudaGetDeviceCount(&devices);
    /* Sync type */
    ERROR_CHECK(cudaSetDeviceFlags(cudaDeviceScheduleSpin));

    /* Display amount of devices */
    std::cout << "|**********************/" << std::endl;
    std::cout << "|    " << devices << " device(s) found" << std::endl;
    std::cout << "|    " << BLOCKS << " blocks found" << std::endl;
    std::cout << "|    " << THREADS << " threads found" << std::endl;
    std::cout << "|**********************/" << std::endl;

    //uint32_t md5Hash[4];
    uint32_t sha1Hash[5];
    uint8 sha256Unhexed[33];
    uint8* unh;

    uint8 sha1Unh[21];
    uint8* sha1_;

    uint8 md5Unh[16];
    uint8* md5_;

    switch (hash_size) {
    case 32: 
        /* Parse argument (md5) */
        std::cout << "It's a MD5" << std::endl;
        for (uint8_t i = 0; i < 4; i++) {
            char tmp[16];
            strncpy(tmp, hash + i * 8, 8);
            sscanf(tmp, "%x", &md5Hash[i]);
            md5Hash[i] = (md5Hash[i] & 0xFF000000) >> 24 | (md5Hash[i] & 0x00FF0000) >> 8 | (md5Hash[i] & 0x0000FF00) << 8 | (md5Hash[i] & 0x000000FF) << 24;
        }
        memset(md5Unh, 0, 16);
        hex_to_string(md5Unh, 16, hash, 32);
        cudaMalloc((char**)&md5_, sizeof(char) * 16);
        cudaMemcpy(md5_, md5Unh, sizeof(char) * 16, cudaMemcpyHostToDevice);
        break;
    case 40: 
        /* Parse argument (sha1) */ 
        std::cout << "It's a SHA1" << std::endl;
          /*char tmp[40];
          for (int i = 0; i < 5; i++)
          {
              for (int j = 0; j < 8; j++)
                  tmp[j] = hash[i * 8 + j];

              sha1Hash[i] = (uint32_t)strtoll(tmp, NULL, 16);
          }*/
          memset(sha1Unh, 0, 21);
          hex_to_string(sha1Unh, 20, hash, 40);
          cudaMalloc((char**)&sha1_, sizeof(char) * 20);
          cudaMemcpy(sha1_, sha1Unh, sizeof(char) * 20, cudaMemcpyHostToDevice);
        break;
    case 64: 
        /* Parse argument (sha256) */
        std::cout << "It's a SHA256" << std::endl;
        memset(sha256Unhexed, 0, 33);
        hex_to_string(sha256Unhexed, 32, hash, 64);
        
        cudaMalloc((char**)&unh, sizeof(char) * 32);
        cudaMemcpy(unh, sha256Unhexed, sizeof(char) * 32, cudaMemcpyHostToDevice);

        break;
    default: 
        std::cout << "Wrong hash length" << std::endl;
        return -1;
    }

    /* Fill memory */
    memset(g_word, 0, CONST_WORD_LIMIT);
    memset(g_cracked, 0, CONST_WORD_LIMIT);
    memcpy(g_charset, CONST_CHARSET, CONST_CHARSET_LENGTH);

    /* Current word length = minimum word length */
    g_wordLength = CONST_WORD_LENGTH_MIN;

    /* Main device */
    cudaSetDevice(0);

    /* Timers */
    cudaEvent_t clockBegin;
    cudaEvent_t clockLast;

    cudaEventCreate(&clockBegin, cudaEventDefault);
    cudaEventCreate(&clockLast, cudaEventDefault);
    cudaEventRecord(clockBegin, 0);

    /* Current word is different on each device */
    char** words = new char* [devices];

    for (int device = 0; device < devices; device++) {
        cudaSetDevice(device);

        /* Copy to each device */
        ERROR_CHECK(cudaMemcpyToSymbol(g_deviceCharset, g_charset, sizeof(uint8_t) * CONST_CHARSET_LIMIT, 0, cudaMemcpyHostToDevice));
        ERROR_CHECK(cudaMemcpyToSymbol(g_deviceCracked, g_cracked, sizeof(uint8_t) * CONST_WORD_LIMIT, 0, cudaMemcpyHostToDevice));

        /* Allocate on each device */
        ERROR_CHECK(cudaMalloc((void**)&words[device], sizeof(uint8_t) * CONST_WORD_LIMIT));
    }

    int later = 0;
    while (true) {
        bool result = false;
        bool found = false;

        for (int device = 0; device < devices; device++) {
            cudaSetDevice(device);

            /* Copy current data */
            ERROR_CHECK(cudaMemcpy(words[device], g_word, sizeof(uint8_t) * CONST_WORD_LIMIT, cudaMemcpyHostToDevice));

            /* Start kernel */
            switch (hash_size) {
            case 32: 
                //md5Crack <<< BLOCKS, THREADS >>> (g_wordLength, words[device], md5Hash[0], md5Hash[1], 
                //    md5Hash[2], md5Hash[3]);
                md5Crack2 << < BLOCKS, THREADS >> > (g_wordLength, words[device], md5_);
                break;
            case 40: 
                //sha1Crack <<< BLOCKS, THREADS >>> (g_wordLength, words[device], sha1Hash[0], sha1Hash[1], 
                //    sha1Hash[2], sha1Hash[3], sha1Hash[4]);
                sha1Crack2 << <BLOCKS, THREADS >> > (g_wordLength, words[device], sha1_);
                break;
            case 64: 
                sha256Crack <<< BLOCKS, THREADS >>> (g_wordLength, words[device], unh);
                break;
            default:
                std::cout << "Error when start __global__";
                break;
            }

            /* Global increment */
            result = next(&g_wordLength, g_word, BLOCKS * THREADS);
        }

        ///* Display progress */
        //char word[CONST_WORD_LIMIT];

        //for (int i = 0; i < g_wordLength; i++) {
        //    word[i] = g_charset[g_word[i]];
        //}
        if (later != (uint32_t)g_wordLength) {
            std::cout << "(" << (uint32_t)g_wordLength << ")" << std::endl;
            later = (uint32_t)g_wordLength;
        }
        //std::cout << "currently at " << std::string(word, g_wordLength) << " (" << (uint32_t)g_wordLength << ")" << std::endl;

        for (int device = 0; device < devices; device++) {
            cudaSetDevice(device);
            cudaDeviceSynchronize();
            ERROR_CHECK(cudaMemcpyFromSymbol(g_cracked, g_deviceCracked, sizeof(uint8_t) * CONST_WORD_LIMIT));
            if (found = *g_cracked != 0) {
                std::cout << "cracked " << g_cracked << std::endl;
                break;
            }
        }

        if (!result || found) {
            if (!result && !found) {
                std::cout << "found nothing (host)" << std::endl;
            }

            break;
        }
    }

    for (int device = 0; device < devices; device++) {
        cudaSetDevice(device);
        cudaFree((void**)words[device]);
    }
    delete[] words;
    cudaSetDevice(0);
    float milliseconds = 0;
    cudaEventRecord(clockLast, 0);
    cudaEventSynchronize(clockLast);
    cudaEventElapsedTime(&milliseconds, clockBegin, clockLast);

    std::cout << "Computation time " << milliseconds << " ms" << std::endl;

    cudaEventDestroy(clockBegin);
    cudaEventDestroy(clockLast);
}
