/*
    Generator
    Encryption with Hierocrypt3 (CBC)

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerator.cpp
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16
#define GF8             0x163
#define MAX_ROUND       8

typedef uint8_t HC3_KS[MAX_ROUND + 1][8][4];

const uint8_t SBox[256] =
{
    0x07, 0xFC, 0x55, 0x70, 0x98, 0x8E, 0x84, 0x4E, 0xBC, 0x75, 0xCE, 0x18,
    0x02, 0xE9, 0x5D, 0x80, 0x1C, 0x60, 0x78, 0x42, 0x9D, 0x2E, 0xF5, 0xE8,
    0xC6, 0x7A, 0x2F, 0xA4, 0xB2, 0x5F, 0x19, 0x87, 0x0B, 0x9B, 0x9C, 0xD3,
    0xC3, 0x77, 0x3D, 0x6F, 0xB9, 0x2D, 0x4D, 0xF7, 0x8C, 0xA7, 0xAC, 0x17,
    0x3C, 0x5A, 0x41, 0xC9, 0x29, 0xED, 0xDE, 0x27, 0x69, 0x30, 0x72, 0xA8,
    0x95, 0x3E, 0xF9, 0xD8, 0x21, 0x8B, 0x44, 0xD7, 0x11, 0x0D, 0x48, 0xFD,
    0x6A, 0x01, 0x57, 0xE5, 0xBD, 0x85, 0xEC, 0x1E, 0x37, 0x9F, 0xB5, 0x9A,
    0x7C, 0x09, 0xF1, 0xB1, 0x94, 0x81, 0x82, 0x08, 0xFB, 0xC0, 0x51, 0x0F,
    0x61, 0x7F, 0x1A, 0x56, 0x96, 0x13, 0xC1, 0x67, 0x99, 0x03, 0x5E, 0xB6,
    0xCA, 0xFA, 0x9E, 0xDF, 0xD6, 0x83, 0xCC, 0xA2, 0x12, 0x23, 0xB7, 0x65,
    0xD0, 0x39, 0x7D, 0x3B, 0xD5, 0xB0, 0xAF, 0x1F, 0x06, 0xC8, 0x34, 0xC5,
    0x1B, 0x79, 0x4B, 0x66, 0xBF, 0x88, 0x4A, 0xC4, 0xEF, 0x58, 0x3F, 0x0A,
    0x2C, 0x73, 0xD1, 0xF8, 0x6B, 0xE6, 0x20, 0xB8, 0x22, 0x43, 0xB3, 0x33,
    0xE7, 0xF0, 0x71, 0x7E, 0x52, 0x89, 0x47, 0x63, 0x0E, 0x6D, 0xE3, 0xBE,
    0x59, 0x64, 0xEE, 0xF6, 0x38, 0x5C, 0xF4, 0x5B, 0x49, 0xD4, 0xE0, 0xF3,
    0xBB, 0x54, 0x26, 0x2B, 0x00, 0x86, 0x90, 0xFF, 0xFE, 0xA6, 0x7B, 0x05,
    0xAD, 0x68, 0xA1, 0x10, 0xEB, 0xC7, 0xE2, 0xF2, 0x46, 0x8A, 0x6C, 0x14,
    0x6E, 0xCF, 0x35, 0x45, 0x50, 0xD2, 0x92, 0x74, 0x93, 0xE1, 0xDA, 0xAE,
    0xA9, 0x53, 0xE4, 0x40, 0xCD, 0xBA, 0x97, 0xA3, 0x91, 0x31, 0x25, 0x76,
    0x36, 0x32, 0x28, 0x3A, 0x24, 0x4C, 0xDB, 0xD9, 0x8D, 0xDC, 0x62, 0x2A,
    0xEA, 0x15, 0xDD, 0xC2, 0xA5, 0x0C, 0x04, 0x1D, 0x8F, 0xCB, 0xB4, 0x4F,
    0x16, 0xAB, 0xAA, 0xA0
};

const uint8_t ISBox[256] =
{
    0xB8, 0x49, 0x0C, 0x69, 0xF6, 0xBF, 0x80, 0x00, 0x5B, 0x55, 0x8F, 0x20,
    0xF5, 0x45, 0xA4, 0x5F, 0xC3, 0x44, 0x74, 0x65, 0xCB, 0xF1, 0xFC, 0x2F,
    0x0B, 0x1E, 0x62, 0x84, 0x10, 0xF7, 0x4F, 0x7F, 0x96, 0x40, 0x98, 0x75,
    0xE8, 0xE2, 0xB6, 0x37, 0xE6, 0x34, 0xEF, 0xB7, 0x90, 0x29, 0x15, 0x1A,
    0x39, 0xE1, 0xE5, 0x9B, 0x82, 0xCE, 0xE4, 0x50, 0xAC, 0x79, 0xE7, 0x7B,
    0x30, 0x26, 0x3D, 0x8E, 0xDB, 0x32, 0x13, 0x99, 0x42, 0xCF, 0xC8, 0xA2,
    0x46, 0xB0, 0x8A, 0x86, 0xE9, 0x2A, 0x07, 0xFB, 0xD0, 0x5E, 0xA0, 0xD9,
    0xB5, 0x02, 0x63, 0x4A, 0x8D, 0xA8, 0x31, 0xAF, 0xAD, 0x0E, 0x6A, 0x1D,
    0x11, 0x60, 0xEE, 0xA3, 0xA9, 0x77, 0x87, 0x67, 0xC1, 0x38, 0x48, 0x94,
    0xCA, 0xA5, 0xCC, 0x27, 0x03, 0x9E, 0x3A, 0x91, 0xD3, 0x09, 0xE3, 0x25,
    0x12, 0x85, 0x19, 0xBE, 0x54, 0x7A, 0x9F, 0x61, 0x0F, 0x59, 0x5A, 0x71,
    0x06, 0x4D, 0xB9, 0x1F, 0x89, 0xA1, 0xC9, 0x41, 0x2C, 0xEC, 0x05, 0xF8,
    0xBA, 0xE0, 0xD2, 0xD4, 0x58, 0x3C, 0x64, 0xDE, 0x04, 0x68, 0x53, 0x21,
    0x22, 0x14, 0x6E, 0x51, 0xFF, 0xC2, 0x73, 0xDF, 0x1B, 0xF4, 0xBD, 0x2D,
    0x3B, 0xD8, 0xFE, 0xFD, 0x2E, 0xC0, 0xD7, 0x7E, 0x7D, 0x57, 0x1C, 0x9A,
    0xFA, 0x52, 0x6B, 0x76, 0x97, 0x28, 0xDD, 0xB4, 0x08, 0x4C, 0xA7, 0x88,
    0x5D, 0x66, 0xF3, 0x24, 0x8B, 0x83, 0x18, 0xC5, 0x81, 0x33, 0x6C, 0xF9,
    0x72, 0xDC, 0x0A, 0xCD, 0x78, 0x92, 0xD1, 0x23, 0xB1, 0x7C, 0x70, 0x43,
    0x3F, 0xEB, 0xD6, 0xEA, 0xED, 0xF2, 0x36, 0x6F, 0xB2, 0xD5, 0xC6, 0xA6,
    0xDA, 0x4B, 0x95, 0x9C, 0x17, 0x0D, 0xF0, 0xC4, 0x4E, 0x35, 0xAA, 0x8C,
    0x9D, 0x56, 0xC7, 0xB3, 0xAE, 0x16, 0xAB, 0x2B, 0x93, 0x3E, 0x6D, 0x5C,
    0x01, 0x47, 0xBC, 0xBB
};

const uint8_t HConst[4][4] =
{
    { 0x5A, 0x82, 0x79, 0x99 },
    { 0x6E, 0xD9, 0xEB, 0xA1 },
    { 0x8F, 0x1B, 0xBC, 0xDC },
    { 0xCA, 0x62, 0xC1, 0xD6 }
};

const int32_t GIndex[6][2] = 
{
    { 3, 0 }, { 2, 1 }, { 1, 3 }, 
    { 0, 2 }, { 2, 3 }, { 1, 0 }
};

const int32_t KConst[3][10] =
{
    { 0, 1, 2, 3, 3, 2, 1, -1, -1, -1 },
    { 1, 0, 3, 2, 2, 3, 0,  1, -1, -1 },
    { 4, 0, 2, 1, 3, 3, 1,  2,  0, -1 }
};

const uint8_t MDS[4][4] =
{
    { 0xC4, 0x65, 0xC8, 0x8B },
    { 0x8B, 0xC4, 0x65, 0xC8 },
    { 0xC8, 0x8B, 0xC4, 0x65 },
    { 0x65, 0xC8, 0x8B, 0xC4 }
};

/* Inversion of MDS box */
const uint8_t IMDS[4][4] =
{
    { 0x82, 0xC4, 0x34, 0xF6 },
    { 0xF6, 0x82, 0xC4, 0x34 },
    { 0x34, 0xF6, 0x82, 0xC4 },
    { 0xC4, 0x34, 0xF6, 0x82 }
};

const int32_t MDSH[4][4] =
{
    { 0x5, 0x5, 0xA, 0xE },
    { 0xE, 0x5, 0x5, 0xA },
    { 0xA, 0xE, 0x5, 0x5 },
    { 0x5, 0xA, 0xE, 0x5 }
};

/* Inversion of MDSH */
const int32_t IMDSH[4][4] =
{
    { 0xB, 0xE, 0xE, 0x6 },
    { 0x6, 0xB, 0xE, 0xE },
    { 0xE, 0x6, 0xB, 0xE },
    { 0xE, 0xE, 0x6, 0xB }
};

typedef struct 
{    
    HC3_KS  ks;
    HC3_KS  dks;
} hc3_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void key_setup(hc3_t * config, uint8_t secret[32]);

int32_t  polynom32_degree   (uint32_t a);
uint32_t polynom32_multiply (uint32_t a, uint32_t b);
uint32_t polynom32_mod      (uint32_t a, uint32_t b);

void mdsl  (uint8_t * dst, uint8_t * src);
void imdsl (uint8_t * dst, uint8_t * src);
void xs    (uint8_t * dst, uint8_t * src, uint8_t * k1, uint8_t * k2);
void ixs   (uint8_t * dst, uint8_t * src, uint8_t * k1, uint8_t * k2);

void mdsh_multiply (uint8_t * dst, uint8_t * src, uint32_t x);

void mdsh (uint8_t dst[4][4], uint8_t src[4][4]);
void imdsh(uint8_t dst[4][4], uint8_t src[4][4]);

void keyf (uint8_t * in, uint8_t * fout, uint8_t *fkey);
void keyp (uint8_t kout[8][4], uint8_t k[4][8], uint32_t index);
void keyc (uint8_t kout[8][4], uint8_t k[4][8], uint32_t index);

void swap_key (uint8_t * L, uint8_t * R);


/* *************************** HELPER FUNCTIONS *************************** */
void xor_block(uint8_t * dst, uint8_t * src1, uint8_t * src2)
{
    register uint32_t i = 0;
    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] = src1[i] ^ src2[i];
}

void print_hex(char* header, uint8_t* data, uint32_t length)
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


void block_encrypt(hc3_t * config, uint8_t val[BLOCKSIZEB])
{
    uint8_t t[4][4], u[4][4];
    int32_t i, j, r;
    int32_t n;

    // represent value as matrix
    for (r = i = 0; i < 4; i++)
        for (j = 0; j < 4; j++, r++)
            t[i][j] = val[r];

    n = 7;

    // round 1 - 7
    for (r = 0; r < n; r++)
    {
        xs (&u[0][0], &t[0][0], &config->ks[r][0][0], &config->ks[r][4][0]);
        xs (&u[1][0], &t[1][0], &config->ks[r][1][0], &config->ks[r][5][0]);
        xs (&u[2][0], &t[2][0], &config->ks[r][2][0], &config->ks[r][6][0]);
        xs (&u[3][0], &t[3][0], &config->ks[r][3][0], &config->ks[r][7][0]);
        mdsh (t, u);
    }

    // round 8
    xs (&u[0][0], &t[0][0], &config->ks[n][0][0], &config->ks[n][4][0]);
    xs (&u[1][0], &t[1][0], &config->ks[n][1][0], &config->ks[n][5][0]);
    xs (&u[2][0], &t[2][0], &config->ks[n][2][0], &config->ks[n][6][0]);
    xs (&u[3][0], &t[3][0], &config->ks[n][3][0], &config->ks[n][7][0]);

    // map back from matrix to array
    for (r = i = 0; i < 4; i++)
        for (j = 0; j < 4; j++, r++)
            val[r] = u[i][j] ^ config->ks[n + 1][i][j];
}

// Hierocrypt3 encryption with CBC
void encrypt(uint8_t * data, uint32_t size, uint8_t * key, uint8_t * iv)
{
    hc3_t       config;
    uint32_t    i;
    uint8_t   * prev_block;

    // setup configuration
    key_setup(&config, key);

    prev_block = iv;

    for (i = 0; i < size; i += BLOCKSIZEB)
    {
        // XOR plaintext with previous ciphertext block
        xor_block(&data[i], &data[i], prev_block);

        // encrypt plaintext
        block_encrypt(&config, &data[i]);

        // store ciphertext block for next XOR operation
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
            { 0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 0x31, 0x33, 0x33, 0x37,
    /* ASCII:   R     E     V     E     R     S     I     N     G     .     I     D     1     3     3     7 */
              0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 0x31, 0x33, 0x33, 0x37, };

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


/* ********************* INTERNAL FUNCTIONS IMPLEMENTATION ********************* */
// derive round-key from secret key
void key_setup (hc3_t * config, uint8_t secret[32])
{
    uint8_t k[4][8];
    uint8_t fout[8];
    uint32_t i, j, pos, r, n;

    memset(config->ks,  0, sizeof(config->ks));
    memset(config->dks, 0, sizeof(config->dks));

    pos = 0;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 8; j++)
            k[i][j] = secret[pos++];
    
    mdsh_multiply(&k[2][0], &k[2][0], 5);
    mdsh_multiply(&k[2][4], &k[2][4], 0xE);
    mdsh_multiply(&k[3][0], &k[3][0], 5);
    mdsh_multiply(&k[3][4], &k[3][4], 0xE);

    for (i = 0; i < 4; i++)
        k[2][i    ] ^= HConst[GIndex[5][0]][i];
    
    for (i = 0; i < 4; i++)
        k[2][i + 4] ^= HConst[GIndex[5][1]][i];

    keyf(&k[1][0], fout, &k[2][0]);
    
    for (i = 0; i < 8; i++)
        k[0][i] ^= fout[i];
    
    swap_key(&k[0][0], &k[1][0]);

    for (r = 0; r < 5; r++)
        keyp(&config->ks[r][0], &k[0], KConst[2][r]);

    for (r = 5; r < 9; r++)
        keyc(&config->ks[r][0], &k[0], KConst[2][r]);
    
    r = 8;

    for (j = 0; j < 4; j++)
        for (n = 0; n < 4; n++)
            config->dks[0][j][n] = config->ks[r][j][n];
    
    for (i = 1; i < r; i++)
    {
        for (j = 4; j < 8; j++)
            imdsl(&config->dks[i - 1][j][0], &config->ks[r - i][j][0]);
        imdsh(&config->dks[i][0], &config->ks[r - i][0]);
    }

    for (j = 4; j < 8; j++)
        imdsl(&config->dks[r - 1][j][0], &config->ks[0][j][0]);

    for (j = 0; j < 4; j++)
        for (n = 0; n < 4; n++)
            config->dks[r][j][n] = config->ks[0][j][n];
}

// swap keys from block L to block R
void swap_key (uint8_t * L, uint8_t * R)
{
    uint8_t  t;
    uint32_t i;
    for (i = 0; i < 8; i++)
    {
        t = L[i];
        L[i] = R[i];
        R[i] = t;
    }
}

/*
    Get the degree of polynomial.
    Polynomial is represented as bits.
*/
int32_t polynom32_degree (uint32_t a)
{
    int32_t n = -1;
    for (; a; a >>= 1)
        n ++;
    return n;
}

/*
    Polynom multiplication.
    Polynomial is represented as bits.
*/
uint32_t polynom32_multiply (uint32_t a, uint32_t b)
{
    uint32_t c = 0;
    
    for (; b; b >>= 1, a <<= 1)
        if (b & 1)
            c ^= a;

    return c; 
}

uint32_t polynom32_mod (uint32_t a, uint32_t b)
{
    int32_t da = polynom32_degree(a);
    int32_t db = polynom32_degree(b);

    uint32_t t;

    if (da < db)  return a;

    if (da == db) return a ^ b;

    b <<= da - db;

    for (t = 1 << da; da >= db; da--)
    {
        if (a & t)
            a ^= b;
        b >>= 1;
        t >>= 1;
    }

    return a;
}

/* MDS-L */
void mdsl (uint8_t * dst, uint8_t * src)
{
    int32_t i, j;
    uint32_t m;

    for (i = 0; i < 4; i++)
    {
        m = 0;
        for (j = 0; j < 4; j++)
        {
            m ^= polynom32_mod(polynom32_multiply(MDS[i][j], src[j]), GF8);
        }
        dst[i] = (uint8_t) m;
    }
}

/* Inversi dari MDS-L */
void imdsl (uint8_t * dst, uint8_t * src)
{
    int32_t  i, j;
    uint32_t m;

    for (i = 0; i < 4; i++)
    {
        m = 0;
        for (j = 0; j < 4; j++)
        {
            m ^= polynom32_mod(polynom32_multiply(IMDS[i][j], src[j]), GF8);
        }
        dst[i] = m;
    }
}

void xs (uint8_t * dst, uint8_t * src, uint8_t * k1, uint8_t * k2)
{
    uint8_t t[4], u[4];
    int32_t i;

    for (i = 0; i < 4; i++)
        u[i] = src[i] ^ k1[i];      /* key XOR */

    for (i = 0; i < 4; i++)
        t[i] = SBox[u[i]];          /* S-Box  */

    mdsl (u, t);             /* MDS_L */

    for (i = 0; i < 4; i++)
        t[i] = u[i] ^ k2[i];        /* key XOR */
    
    for (i = 0; i < 4; i++)
        dst[i] = SBox[t[i]];        /* S-Box  */
}

void ixs (uint8_t * dst, uint8_t * src, uint8_t * k1, uint8_t * k2)
{
    uint8_t t[4], u[4];
    int32_t i;

    for (i = 0; i < 4; i++)
        u[i] = src[i] ^ k1[i];      /* key XOR */

    for (i = 0; i < 4; i++)
        t[i] = ISBox[u[i]];         /* S-Box  */

    imdsl (u, t);            /* MDS_L */

    for (i = 0; i < 4; i++)
        t[i] = u[i] ^ k2[i];        /* key xOR */

    for (i = 0; i < 4; i++)
        dst[i] = ISBox[t[i]];       /* S-Box */
}


void mdsh_multiply (uint8_t * dst, uint8_t * src, uint32_t x)
{
    uint32_t i;
    uint8_t  u[4];

    for (i = 0; i < 4; i++)
        u[i] = 0;

    if (x & 1)
    {
        u[0] ^= src[0];
        u[1] ^= src[1];
        u[2] ^= src[2];
        u[3] ^= src[3];
    }

    if (x & 2)
    {
        u[0] ^= src[1];
        u[1] ^= src[2];
        u[2] ^= src[3] ^ src[0];
        u[3] ^= src[0];
    }

    if (x & 4)
    {
        u[0] ^= src[2];
        u[1] ^= src[3] ^ src[0];
        u[2] ^= src[0] ^ src[1];
        u[3] ^= src[1];
    }

    if (x & 8)
    {
        u[0] ^= src[0] ^ src[3];
        u[1] ^= src[1] ^ src[0];
        u[2] ^= src[2] ^ src[1];
        u[3] ^= src[2];
    }

    for (i = 0; i < 4; i++)
        dst[i] = u[i];
}

void mdsh (uint8_t dst[4][4], uint8_t src[4][4])
{
    uint32_t i, j, k;
    uint8_t  tmp[4];

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            dst[i][j] = 0;
    
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            mdsh_multiply (tmp, &src[j][0], MDSH[i][j]);
            
            for (k = 0; k < 4; k++)
                dst[i][k] ^= tmp[k];
        }
    }
}

void imdsh(uint8_t dst[4][4], uint8_t src[4][4])
{
    int32_t i, j, k;
    uint8_t tmp[4];

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            dst[i][j] = 0;
    
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            mdsh_multiply (tmp, &src[j][0], IMDSH[i][j]);

            for (k = 0; k < 4; k++)
                dst[i][k] ^= tmp[k];
        }
    }
}

void keyf (uint8_t * in, uint8_t * fout, uint8_t *fkey)
{
    int32_t i;

    /* F in */
    for (i = 0; i < 8; i++)
        fout[i] = SBox[in[i] ^ fkey[i]];

    fout[0] ^= fout[4];
    fout[1] ^= fout[5];
    fout[2] ^= fout[6];
    fout[3] ^= fout[7];
    fout[4] ^= fout[2];
    fout[5] ^= fout[3];
    fout[6] ^= fout[0];
    fout[7] ^= fout[1];
}

void keyp (uint8_t kout[8][4], uint8_t k[4][8], uint32_t index)
{
    int32_t i;
    uint8_t fout[8];

    /* P(32) */
    for (i = 0; i < 4; i++)
    {
        k[2][i    ] ^= k[3][i    ];
        k[2][i + 4] ^= k[3][i + 4];
    }
    for (i = 0; i < 4; i++)
    {
        k[3][i    ] ^= k[2][i + 4];
        k[3][i + 4] ^= k[2][i    ];
    }

    /* multiple */
    mdsh_multiply (&k[2][0], &k[2][0], 5);
    mdsh_multiply (&k[2][4], &k[2][4], 0xE);
    mdsh_multiply (&k[3][0], &k[3][0], 5);
    mdsh_multiply (&k[3][4], &k[3][4], 0xE);

    for (i = 0; i < 4; i++)
        k[2][i    ] ^= HConst[GIndex[index][0]][i];

    for (i = 0; i < 4; i++)
        k[2][i + 4] ^= HConst[GIndex[index][1]][i];

    keyf (&k[1][0], fout, &k[2][0]);

    for (i = 0; i < 8; i++)
        k[0][i] ^= fout[i];         /* L xor f(R) */

    for (i = 0; i < 4; i++)
    {
        kout[0][i] = k[0][i    ];
        kout[1][i] = k[0][i + 4];
    }

    for (i = 0; i < 4; i++)
    {
        kout[2][i] = fout[i    ] ^ k[2][i    ];
        kout[3][i] = fout[i + 4] ^ k[2][i + 4];
    }

    for (i = 0; i < 4; i++)
    {
        kout[4][i] = fout[i    ] ^ k[3][i    ];
        kout[5][i] = fout[i + 4] ^ k[3][i + 4];
    }

    for (i = 0; i < 4; i++)
    {
        kout[6][i] = k[1][i    ] ^ k[3][i    ];
        kout[7][i] = k[1][i + 4] ^ k[3][i + 4];
    }

    swap_key (&k[0][0], &k[1][0]);
}

void keyc (uint8_t kout[8][4], uint8_t k[4][8], uint32_t index)
{
    int32_t i;
    uint8_t fout[8];

    swap_key (&k[0][0], &k[1][0]);
    keyf (&k[1][0], fout, &k[2][0]);

    for (i = 0; i < 8; i++)
        k[0][i] ^= fout[i];

    for (i = 0; i < 4; i++)
    {
        kout[0][i] = k[0][i    ] ^ k[2][i    ];
        kout[1][i] = k[0][i + 4] ^ k[2][i + 4];
    }

    for (i = 0; i < 4; i++)
        k[2][i    ] ^= HConst[GIndex[index][0]][i];


    for (i = 0; i < 4; i++)
        k[2][i + 4] ^= HConst[GIndex[index][1]][i];

    mdsh_multiply (&k[2][0], &k[2][0], 0xB);
    mdsh_multiply (&k[2][4], &k[2][4], 0x3);
    mdsh_multiply (&k[3][0], &k[3][0], 0xB);
    mdsh_multiply (&k[3][4], &k[3][4], 0x3);

    for (i = 0; i < 4; i++)
    {
        kout[2][i] = fout[i    ] ^ k[2][i    ];
        kout[3][i] = fout[i + 4] ^ k[2][i + 4];
    }

    for (i = 0; i < 4; i++)
    {
        kout[4][i] = fout[i    ] ^ k[3][i    ];
        kout[5][i] = fout[i + 4] ^ k[3][i + 4];
    }

    for (i = 0; i < 4; i++)
    {
        kout[6][i] = k[1][i    ] ^ k[3][i    ];
        kout[7][i] = k[1][i + 4] ^ k[3][i + 4];
    }

    for (i = 0; i < 4; i++)
    {
        k[3][i    ] ^= k[2][i + 4];
        k[3][i + 4] ^= k[2][i    ];
    }

    for (i = 0; i < 4; i++)
    {
        k[2][i    ] ^= k[3][i    ];
        k[2][i + 4] ^= k[3][i + 4];
    }
}