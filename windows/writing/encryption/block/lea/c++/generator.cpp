/*
    Generator
    Encryption with Blowfish (CBC)

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerator.cpp
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16

#ifdef _MSC_VER
    #include <stdlib.h>
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else 
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif

const uint32_t delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};


/* context and configuration */
typedef struct 
{
    uint32_t bits;
    uint32_t rounds;
    uint32_t rkeys[256];
} lea_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt (lea_t * config, uint8_t * val);
void key_setup(lea_t * config, uint8_t * secret, uint32_t bits);


/* *************************** HELPER FUNCTIONS *************************** */
/* XOR 2 block data */
void xor_block(uint8_t * dst, uint8_t * src1, uint8_t * src2)
{
    register uint32_t i = 0;
    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] = src1[i] ^ src2[i];
}

void print_hex(char* header, uint8_t * data, uint32_t length)
{
    printf("%s = {", header);
    for (int idx = 0; idx < length; idx++)
    {
        if (idx % 16 == 0)
            printf("\n  ");
    
        printf("0x%02x, ", data[idx]);
    }
    printf("\n}\n");
    printf("Length: %d\n", length);
}


// Blowfish encryption with CBC
void encrypt (uint8_t * data, uint32_t size, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    lea_t      config;
    uint8_t  * prev_block = iv;

    // configure key
    key_setup(&config, key, KEYSIZE);

    for (i = 0; i < size; i += BLOCKSIZEB)
    {
        // XOR block plaintext dengan block ciphertext sebelumnya
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi plaintext menjadi ciphertext
        block_encrypt(&config, &data[i]);;

        // Simpan block ciphertext untuk operasi XOR selanjutnya
        prev_block = &data[i];
    }
}

int main()
{
    HANDLE f;
    SIZE_T payload_len, alloc_size, remainder;
    DWORD  nread;

    uint8_t * payload;

    // static key because the key is awesome
    uint8_t   key[] = 
            { 0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 
    /* ASCII:   R     E     V     E     R     S     I     N     G     .     I     D  */
              0x31, 0x33, 0x33, 0x37 };
            /*  1     3     3     7  */

    // generate IV, this example is not cryptographically secure
    uint8_t   iv[BLOCKSIZEB];

    srand(time(0));
    for (int i = 0; i < BLOCKSIZEB; i++)
        iv[i] = rand() % 0xFF;

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // allocate enough space for payload blocks and IV
    payload_len = GetFileSize (f, NULL);
    remainder   = payload_len % BLOCKSIZEB;
    alloc_size  = payload_len + (remainder ? BLOCKSIZEB - remainder : 0);

    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, alloc_size + BLOCKSIZEB);

    // read the shellcode
    memset(payload, 0x90, alloc_size);
    ReadFile(f, payload, payload_len, &nread, NULL);

    // encrypt the shellcode
    memcpy (&payload[alloc_size], iv, BLOCKSIZEB);
    encrypt (payload, alloc_size, key, iv);

    // print
    print_hex("IV", iv, BLOCKSIZEB);
    print_hex("Payload", payload, alloc_size + BLOCKSIZEB);

    // destroy heap
    HeapFree (GetProcessHeap(), 0, payload);
}

void block_encrypt(lea_t * config, uint8_t * val)
{
    // block: 32 * 4 = 128 bit
    uint32_t * rkeys  = config->rkeys;
    uint32_t   rounds = config->rounds;
    uint32_t   current[4], next[4];
    size_t     idx;

    memcpy(current, val, 16);

    for (idx = 0; idx < rounds; idx++)
    {
        next[0] = rotl((current[0] ^ rkeys[idx * 6    ]) + (current[1] ^ rkeys[idx * 6 + 1]), 9);
		next[1] = rotr((current[1] ^ rkeys[idx * 6 + 2]) + (current[2] ^ rkeys[idx * 6 + 3]), 5);
		next[2] = rotr((current[2] ^ rkeys[idx * 6 + 4]) + (current[3] ^ rkeys[idx * 6 + 5]), 3);
		next[3] = current[0];

        memcpy(current, next, 16);
    }

    memcpy(val, next, 16);
}

void 
key_setup(lea_t * config, uint8_t * secret, uint32_t bits)
{
    uint32_t   T[8];
    size_t     idx;

    config->bits = bits;
    memcpy(T, secret, config->bits / 8);
    memset(config->rkeys, 0, sizeof(config->rkeys));

    // generate round keys
    if (config->bits == 128)
    {
        config->rounds = 24;
        for (idx = 0; idx < config->rounds; idx++)
        {
            T[0] = rotl(T[0] + rotl(idx    , delta[idx % 4]),  1);
            T[1] = rotl(T[1] + rotl(idx + 1, delta[idx % 4]),  3);
            T[2] = rotl(T[2] + rotl(idx + 2, delta[idx % 4]),  6);
            T[3] = rotl(T[3] + rotl(idx + 3, delta[idx % 4]), 11);

            config->rkeys[idx * 6    ] = T[0];
            config->rkeys[idx * 6 + 1] = T[1];
            config->rkeys[idx * 6 + 2] = T[2];
            config->rkeys[idx * 6 + 3] = T[1];
            config->rkeys[idx * 6 + 4] = T[3];
            config->rkeys[idx * 6 + 5] = T[1];
        }
    }
    else if (config->bits == 192)
    {
        config->rounds = 28;
        for (idx = 0; idx < config->rounds; idx ++)
        {
            T[0] = rotl(T[0] + rotl(idx    , delta[idx % 6]),  1);
            T[1] = rotl(T[1] + rotl(idx + 1, delta[idx % 6]),  3);
            T[2] = rotl(T[2] + rotl(idx + 2, delta[idx % 6]),  6);
            T[3] = rotl(T[3] + rotl(idx + 3, delta[idx % 6]), 11);
            T[4] = rotl(T[4] + rotl(idx + 4, delta[idx % 6]), 13);
            T[5] = rotl(T[5] + rotl(idx + 5, delta[idx % 6]), 17);
            
            config->rkeys[idx * 6    ] = T[0];
            config->rkeys[idx * 6 + 1] = T[1];
            config->rkeys[idx * 6 + 2] = T[2];
            config->rkeys[idx * 6 + 3] = T[3];
            config->rkeys[idx * 6 + 4] = T[4];
            config->rkeys[idx * 6 + 5] = T[5];
        
        }
    }
    else if (config->bits == 256)
    {
        config->rounds = 32;
        for (idx = 0; idx < config->rounds; idx++)
        {
            T[(6 * idx    ) % 8] =rotl(T[(6 * idx    ) % 8] + rotl(idx    , delta[idx % 8]),  1);
            T[(6 * idx + 1) % 8] =rotl(T[(6 * idx + 1) % 8] + rotl(idx + 1, delta[idx % 8]),  3);
            T[(6 * idx + 2) % 8] =rotl(T[(6 * idx + 2) % 8] + rotl(idx + 2, delta[idx % 8]),  6);
            T[(6 * idx + 3) % 8] =rotl(T[(6 * idx + 3) % 8] + rotl(idx + 3, delta[idx % 8]), 11);
            T[(6 * idx + 4) % 8] =rotl(T[(6 * idx + 4) % 8] + rotl(idx + 4, delta[idx % 8]), 13);
            T[(6 * idx + 5) % 8] =rotl(T[(6 * idx + 5) % 8] + rotl(idx + 5, delta[idx % 8]), 17);
            
            config->rkeys[idx * 6    ] = T[(idx * 6    ) % 8];
            config->rkeys[idx * 6 + 1] = T[(idx * 6 + 1) % 8];
            config->rkeys[idx * 6 + 2] = T[(idx * 6 + 2) % 8];
            config->rkeys[idx * 6 + 3] = T[(idx * 6 + 3) % 8];
            config->rkeys[idx * 6 + 4] = T[(idx * 6 + 4) % 8];
            config->rkeys[idx * 6 + 5] = T[(idx * 6 + 5) % 8];
        }
    }
}