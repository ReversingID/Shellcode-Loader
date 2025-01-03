/*
    Generator
    Encryption with SAFER+ (CBC)

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerator.cpp
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE   128
#define BLOCKSIZEB  16
#define KEYSIZE     128
#define KEYSIZEB    16
#define ROUNDS      6

uint8_t _expf[256] =
{
      1,  45, 226, 147, 190,  69,  21, 174, 120,   3, 135, 164, 184,  56, 207,  63,
      8, 103,   9, 148, 235,  38, 168, 107, 189,  24,  52,  27, 187, 191, 114, 247,
     64,  53,  72, 156,  81,  47,  59,  85, 227, 192, 159, 216, 211, 243, 141, 177,
    255, 167,  62, 220, 134, 119, 215, 166,  17, 251, 244, 186, 146, 145, 100, 131,
    241,  51, 239, 218,  44, 181, 178,  43, 136, 209, 153, 203, 140, 132,  29,  20,
    129, 151, 113, 202,  95, 163, 139,  87,  60, 130, 196,  82,  92,  28, 232, 160,
      4, 180, 133,  74, 246,  19,  84, 182, 223,  12,  26, 142, 222, 224,  57, 252,
     32, 155,  36,  78, 169, 152, 158, 171, 242,  96, 208, 108, 234, 250, 199, 217,
      0, 212,  31, 110,  67, 188, 236,  83, 137, 254, 122,  93,  73, 201,  50, 194,
    249, 154, 248, 109,  22, 219,  89, 150,  68, 233, 205, 230,  70,  66, 143,  10,
    193, 204, 185, 101, 176, 210, 198, 172,  30,  65,  98,  41,  46,  14, 116,  80,
      2,  90, 195,  37, 123, 138,  42,  91, 240,   6,  13,  71, 111, 112, 157, 126,
     16, 206,  18,  39, 213,  76,  79, 214, 121,  48, 104,  54, 117, 125, 228, 237,
    128, 106, 144,  55, 162,  94, 118, 170, 197, 127,  61, 175, 165, 229,  25,  97,
    253,  77, 124, 183,  11, 238, 173,  75,  34, 245, 231, 115,  35,  33, 200,   5,
    225, 102, 221, 179,  88, 105,  99,  86,  15, 161,  49, 149,  23,   7,  58,  40 
};

uint8_t _logf[512] = 
{
    128,   0, 176,   9,  96, 239, 185, 253,  16,  18, 159, 228, 105, 186, 173, 248,
    192,  56, 194, 101,  79,   6, 148, 252,  25, 222, 106,  27,  93,  78, 168, 130,
    112, 237, 232, 236, 114, 179,  21, 195, 255, 171, 182,  71,  68,   1, 172,  37,
    201, 250, 142,  65,  26,  33, 203, 211,  13, 110, 254,  38,  88, 218,  50,  15,
     32, 169, 157, 132, 152,   5, 156, 187,  34, 140,  99, 231, 197, 225, 115, 198,
    175,  36,  91, 135, 102,  39, 247,  87, 244, 150, 177, 183,  92, 139, 213,  84,
    121, 223, 170, 246,  62, 163, 241,  17, 202, 245, 209,  23, 123, 147, 131, 188,
    189,  82,  30, 235, 174, 204, 214,  53,   8, 200, 138, 180, 226, 205, 191, 217,
    208,  80,  89,  63,  77,  98,  52,  10,  72, 136, 181,  86,  76,  46, 107, 158,
    210,  61,  60,   3,  19, 251, 151,  81, 117,  74, 145, 113,  35, 190, 118,  42,
     95, 249, 212,  85,  11, 220,  55,  49,  22, 116, 215, 119, 167, 230,   7, 219,
    164,  47,  70, 243,  97,  69, 103, 227,  12, 162,  59,  28, 133,  24,   4,  29,
     41, 160, 143, 178,  90, 216, 166, 126, 238, 141,  83,  75, 161, 154, 193,  14,
    122,  73, 165,  44, 129, 196, 199,  54,  43, 127,  67, 149,  51, 242, 108, 104,
    109, 240,   2,  40, 206, 221, 155, 234,  94, 153, 124,  20, 134, 207, 229,  66,
    184,  64, 120,  45,  58, 233, 100,  31, 146, 144, 125,  57, 111, 224, 137,  48,

    128,   0, 176,   9,  96, 239, 185, 253,  16,  18, 159, 228, 105, 186, 173, 248,
    192,  56, 194, 101,  79,   6, 148, 252,  25, 222, 106,  27,  93,  78, 168, 130,
    112, 237, 232, 236, 114, 179,  21, 195, 255, 171, 182,  71,  68,   1, 172,  37,
    201, 250, 142,  65,  26,  33, 203, 211,  13, 110, 254,  38,  88, 218,  50,  15,
     32, 169, 157, 132, 152,   5, 156, 187,  34, 140,  99, 231, 197, 225, 115, 198,
    175,  36,  91, 135, 102,  39, 247,  87, 244, 150, 177, 183,  92, 139, 213,  84,
    121, 223, 170, 246,  62, 163, 241,  17, 202, 245, 209,  23, 123, 147, 131, 188,
    189,  82,  30, 235, 174, 204, 214,  53,   8, 200, 138, 180, 226, 205, 191, 217,
    208,  80,  89,  63,  77,  98,  52,  10,  72, 136, 181,  86,  76,  46, 107, 158,
    210,  61,  60,   3,  19, 251, 151,  81, 117,  74, 145, 113,  35, 190, 118,  42,
     95, 249, 212,  85,  11, 220,  55,  49,  22, 116, 215, 119, 167, 230,   7, 219,
    164,  47,  70, 243,  97,  69, 103, 227,  12, 162,  59,  28, 133,  24,   4,  29,
     41, 160, 143, 178,  90, 216, 166, 126, 238, 141,  83,  75, 161, 154, 193,  14,
    122,  73, 165,  44, 129, 196, 199,  54,  43, 127,  67, 149,  51, 242, 108, 104,
    109, 240,   2,  40, 206, 221, 155, 234,  94, 153, 124,  20, 134, 207, 229,  66,
    184,  64, 120,  45,  58, 233, 100,  31, 146, 144, 125,  57, 111, 224, 137,  48
};

// context and configuration
typedef struct 
{
    uint8_t  l_key[33 * 16];
    uint32_t k_bytes;
} safer_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt (safer_t * config, uint8_t * data);
void key_setup (safer_t * config, uint8_t * key, const uint32_t length);

void do_fr (uint8_t val[BLOCKSIZEB], uint8_t * kp);
void do_ir (uint8_t val[BLOCKSIZEB], uint8_t * kp);


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


// SAFER+ encryption with CBC
void encrypt (uint8_t * data, uint32_t size, uint8_t * key, uint8_t * iv)
{
    safer_t    config;
    uint32_t   i;
    uint8_t  * prev_block = iv;

    // configure
    key_setup(&config, key, KEYSIZEB);

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

void block_encrypt(safer_t * config, uint8_t data[BLOCKSIZEB])
{
    uint32_t    block[16];
    uint32_t  * __data = (uint32_t*)data;
    uint32_t    i, m;
    uint8_t   * kp;
    uint8_t   * blk = (uint8_t*)block;

    for (i = 0, m = BLOCKSIZEB/4; i < m; i++)
        block[i] = __data[m - i - 1];

    do_fr(blk, config->l_key);
	do_fr(blk, config->l_key + 32);
	do_fr(blk, config->l_key + 64);
	do_fr(blk, config->l_key + 96);
	do_fr(blk, config->l_key + 128);
	do_fr(blk, config->l_key + 160);
	do_fr(blk, config->l_key + 192);
	do_fr(blk, config->l_key + 224);

	if (config->k_bytes > 16) {
		do_fr(blk, config->l_key + 256);
		do_fr(blk, config->l_key + 288);
		do_fr(blk, config->l_key + 320);
		do_fr(blk, config->l_key + 352);
	}

	if (config->k_bytes > 24) {
		do_fr(blk, config->l_key + 384);
		do_fr(blk, config->l_key + 416);
		do_fr(blk, config->l_key + 448);
		do_fr(blk, config->l_key + 480);
	}

	kp = config->l_key + 16 * config->k_bytes;

	blk[ 0] ^= kp[ 0];
	blk[ 1] += kp[ 1];
	blk[ 2] += kp[ 2];
	blk[ 3] ^= kp[ 3];
	blk[ 4] ^= kp[ 4];
	blk[ 5] += kp[ 5];
	blk[ 6] += kp[ 6];
	blk[ 7] ^= kp[ 7];
	blk[ 8] ^= kp[ 8];
	blk[ 9] += kp[ 9];
	blk[10] += kp[10];
	blk[11] ^= kp[11];
	blk[12] ^= kp[12];
	blk[13] += kp[13];
	blk[14] += kp[14];
	blk[15] ^= kp[15];

	__data[3] = block[0];
	__data[2] = block[1];
	__data[1] = block[2];
	__data[0] = block[3];
}

/*
    Key scheduling and setup the configuration
    Internally key will be casted as integer.
*/
void key_setup(safer_t * config, uint8_t * key, const uint32_t length)
{
    uint32_t    blk[9];     // at least 33 bytes
    uint8_t     by;
    uint8_t   * lk    = (uint8_t*)blk;
    uint32_t  * lk_p  = (uint32_t*)lk;
    uint32_t  * key_p = (uint32_t*)key;
    uint32_t    i, j, k, l, m;

    // set data block
    memset(blk, 0, sizeof(blk));
    for (i = 0, m = length/4; i < m; i++)
        lk_p[i] = key_p[m - i - 1];

    config->k_bytes = KEYSIZEB;     // 16 | 24 | 32
    lk[config->k_bytes] = 0;

    for (i = 0; i < config->k_bytes; i++)
    {
        lk[config->k_bytes] ^= lk[i];
        config->l_key[i] = lk[i];
    }

    for (i = 0; i < config->k_bytes; i++)
    {
        for (j = 0; j <= config->k_bytes; j++)
        {
            by = lk[j];
            lk[j] = by << 3 | by >> 5;
        }

        k = 17 * i + 35;
        l = 16 * i + 16;
        m = i + 1;

        if (i < 16)
        {
            for (j = 0; j < 16; j++)
            {
                config->l_key[l + j] = lk[m] + _expf[_expf[(k + j) & 255]];
                m = (m == config->k_bytes ? 0 : m + 1);
            }
        }
        else 
        {
            for (j = 0; j < 16; j++)
            {
                config->l_key[l + j] = lk[m] + _expf[(k + j) & 255];
                m = (m == config->k_bytes ? 0 : m + 1);
            }
        }
    }
}

void do_fr (uint8_t val[BLOCKSIZEB], uint8_t * kp)
{
    uint8_t t;

    val[ 0] = _expf[val[ 0] ^ kp[ 0]] + kp[16];
    val[ 1] = _logf[val[ 1] + kp[ 1]] ^ kp[17];
    val[ 2] = _logf[val[ 2] + kp[ 2]] ^ kp[18];
    val[ 3] = _expf[val[ 3] ^ kp[ 3]] + kp[19];

    val[ 4] = _expf[val[ 4] ^ kp[ 4]] + kp[20];
    val[ 5] = _logf[val[ 5] + kp[ 5]] ^ kp[21];
    val[ 6] = _logf[val[ 6] + kp[ 6]] ^ kp[22];
    val[ 7] = _expf[val[ 7] ^ kp[ 7]] + kp[23];

    val[ 8] = _expf[val[ 8] ^ kp[ 8]] + kp[24];
    val[ 9] = _logf[val[ 9] + kp[ 9]] ^ kp[25];
    val[10] = _logf[val[10] + kp[10]] ^ kp[26];
    val[11] = _expf[val[11] ^ kp[11]] + kp[27];

    val[12] = _expf[val[12] ^ kp[12]] + kp[28];
    val[13] = _logf[val[13] + kp[13]] ^ kp[29];
    val[14] = _logf[val[14] + kp[14]] ^ kp[30];
    val[15] = _expf[val[15] ^ kp[15]] + kp[31];

    val[ 1] += val[ 0]; val[ 0] += val[ 1];
    val[ 3] += val[ 2]; val[ 2] += val[ 3];
    val[ 5] += val[ 4]; val[ 4] += val[ 5];
    val[ 7] += val[ 6]; val[ 6] += val[ 7];
    val[ 9] += val[ 8]; val[ 8] += val[ 9];
    val[11] += val[10]; val[10] += val[11];
    val[13] += val[12]; val[12] += val[13];
    val[15] += val[14]; val[14] += val[15];

    val[ 7] += val[ 0]; val[ 0] += val[ 7];
    val[ 1] += val[ 2]; val[ 2] += val[ 1];
    val[ 3] += val[ 4]; val[ 4] += val[ 3];
    val[ 5] += val[ 6]; val[ 6] += val[ 5];
    val[11] += val[ 8]; val[ 8] += val[11];
    val[ 9] += val[10]; val[10] += val[ 9];
    val[15] += val[12]; val[12] += val[15];
    val[13] += val[14]; val[14] += val[13];

    val[ 3] += val[ 0]; val[ 0] += val[ 3];
    val[15] += val[ 2]; val[ 2] += val[15];
    val[ 7] += val[ 4]; val[ 4] += val[ 7];
    val[ 1] += val[ 6]; val[ 6] += val[ 1];
    val[ 5] += val[ 8]; val[ 8] += val[ 5];
    val[13] += val[10]; val[10] += val[13];
    val[11] += val[12]; val[12] += val[11];
    val[ 9] += val[14]; val[14] += val[ 9];

    val[13] += val[ 0]; val[ 0] += val[13];
    val[ 5] += val[ 2]; val[ 2] += val[ 5];
    val[ 9] += val[ 4]; val[ 4] += val[ 9];
    val[11] += val[ 6]; val[ 6] += val[11];
    val[15] += val[ 8]; val[ 8] += val[15];
    val[ 1] += val[10]; val[10] += val[ 1];
    val[ 3] += val[12]; val[12] += val[ 3];
    val[ 7] += val[14]; val[14] += val[ 7];

    t = val[ 0]; 
        val[ 0] = val[14]; 
        val[14] = val[12]; 
        val[12] = val[10]; 
        val[10] = val[ 2];
        val[ 2] = val[ 8]; 
        val[ 8] = val[ 4]; 
        val[4] = t;

    t = val[ 1]; 
        val[ 1] = val[ 7];
        val[ 7] = val[11];
        val[11] = val[ 5];
        val[ 5] = val[13];
        val[13] = t;
    t = val[15]; 
        val[15] = val[3]; 
        val[ 3] = t;
}

void do_ir (uint8_t val[BLOCKSIZEB], uint8_t * kp)
{
    uint8_t  t;

    t = val[ 3]; 
        val[ 3] = val[15]; 
        val[15] = t;
    t = val[13]; 
        val[13] = val[ 5]; 
        val[ 5] = val[11]; 
        val[11] = val[ 7]; 
        val[ 7] = val[ 1]; 
        val[ 1] = t;
    t = val[ 4]; 
        val[ 4] = val[ 8]; 
        val[ 8] = val[ 2]; 
        val[ 2] = val[10];
        val[10] = val[12]; 
        val[12] = val[14]; 
        val[14] = val[ 0]; 
        val[ 0] = t;

    val[14] -= val[ 7]; val[ 7] -= val[14];
    val[12] -= val[ 3]; val[ 3] -= val[12];
    val[10] -= val[ 1]; val[ 1] -= val[10];
    val[ 8] -= val[15]; val[15] -= val[ 8];
    val[ 6] -= val[11]; val[11] -= val[ 6];
    val[ 4] -= val[ 9]; val[ 9] -= val[ 4];
    val[ 2] -= val[ 5]; val[ 5] -= val[ 2];
    val[ 0] -= val[13]; val[13] -= val[ 0];

    val[14] -= val[ 9]; val[ 9] -= val[14];
    val[12] -= val[11]; val[11] -= val[12];
    val[10] -= val[13]; val[13] -= val[10];
    val[ 8] -= val[ 5]; val[ 5] -= val[ 8];
    val[ 6] -= val[ 1]; val[ 1] -= val[ 6];
    val[ 4] -= val[ 7]; val[ 7] -= val[ 4];
    val[ 2] -= val[15]; val[15] -= val[ 2];
    val[ 0] -= val[ 3]; val[ 3] -= val[ 0];

    val[14] -= val[13]; val[13] -= val[14];
    val[12] -= val[15]; val[15] -= val[12];
    val[10] -= val[ 9]; val[ 9] -= val[10];
    val[ 8] -= val[11]; val[11] -= val[ 8];
    val[ 6] -= val[ 5]; val[ 5] -= val[ 6];
    val[ 4] -= val[ 3]; val[ 3] -= val[ 4];
    val[ 2] -= val[ 1]; val[ 1] -= val[ 2];
    val[ 0] -= val[ 7]; val[ 7] -= val[ 0];

    val[14] -= val[15]; val[15] -= val[14];
    val[12] -= val[13]; val[13] -= val[12];
    val[10] -= val[11]; val[11] -= val[10];
    val[ 8] -= val[ 9]; val[ 9] -= val[ 8];
    val[ 6] -= val[ 7]; val[ 7] -= val[ 6];
    val[ 4] -= val[ 5]; val[ 5] -= val[ 4];
    val[ 2] -= val[ 3]; val[ 3] -= val[ 2];
    val[ 0] -= val[ 1]; val[ 1] -= val[ 0];    

    val[ 0] = _logf[val[ 0] - kp[16] + 256] ^ kp[ 0];
    val[ 1] = _expf[val[ 1] ^ kp[17]] - kp[ 1];
    val[ 2] = _expf[val[ 2] ^ kp[18]] - kp[ 2];
    val[ 3] = _logf[val[ 3] - kp[19] + 256] ^ kp[ 3];

    val[ 4] = _logf[val[ 4] - kp[20] + 256] ^ kp[ 4];
    val[ 5] = _expf[val[ 5] ^ kp[21]] - kp[ 5];
    val[ 6] = _expf[val[ 6] ^ kp[22]] - kp[ 6];
    val[ 7] = _logf[val[ 7] - kp[23] + 256] ^ kp[ 7];

    val[ 8] = _logf[val[ 8] - kp[24] + 256] ^ kp[ 8];
    val[ 9] = _expf[val[ 9] ^ kp[25]] - kp[ 9];
    val[10] = _expf[val[10] ^ kp[26]] - kp[10];
    val[11] = _logf[val[11] - kp[27] + 256] ^ kp[11];

    val[12] = _logf[val[12] - kp[28] + 256] ^ kp[12];
    val[13] = _expf[val[13] ^ kp[29]] - kp[13];
    val[14] = _expf[val[14] ^ kp[30]] - kp[14];
    val[15] = _logf[val[15] - kp[31] + 256] ^ kp[15];
}