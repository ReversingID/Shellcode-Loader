/*
    Generator
    Encryption with Anubis (CBC)

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerator.cpp
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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


void block_encrypt(uint8_t * data, uint8_t * key)
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

    rndcon_gen(STRT_E, rcon);
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

    for (i = 0; i < 3; i++)
#ifdef LITTLE_ENDIAN
        p_data[i] = bswap32(_data[i]);
#else 
        p_data[i] = _data[i];
#endif 
}

// Anubis encryption with CBC
void encrypt (uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t  * prev_block = iv;

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // XOR block plaintext dengan block ciphertext sebelumnya
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi plaintext menjadi ciphertext
        block_encrypt(&data[i], key);

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

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    remainder   = payload_len % BLOCKSIZEB;
    alloc_size  = payload_len + (remainder ? BLOCKSIZEB - remainder : 0);

    // add space for IV
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