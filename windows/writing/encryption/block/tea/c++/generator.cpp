/*
    Generator
    Encryption with Tiny Encryption Algorithm (TEA).

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp

Note:
    encrypt with CBC mode.
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>


#define BLOCKSIZEB      8
#define ROUNDS          32

#ifdef _MSC_VER
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else 
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif

#define bswap32(x)      (rotl(x,8) & 0x00FF00FF | rotr(x, 8) & 0xFF00FF00)

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

#ifdef LITTLE_ENDIAN
    #define convert(x)   bswap32(x)
#else
    #define convert(x)   (x)
#endif


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


void block_encrypt (uint8_t * val, uint8_t * key)
{
    uint32_t  * p_val = (uint32_t*)val;
    uint32_t  * p_key = (uint32_t*)key;

    uint32_t    v0 = convert(p_val[0]), v1 = convert(p_val[1]);
    uint32_t    k0 = convert(p_key[0]), k1 = convert(p_key[1]), 
                k2 = convert(p_key[2]), k3 = convert(p_key[3]);
    uint32_t    delta = 0x9E3779B9, sum = 0, i;

    // Round: 32
    for (i =  0; i < ROUNDS; i++)
    {
        // Round-Function
        sum += delta;
        v0  += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1  += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }

    p_val[0] = convert(v0);
    p_val[1] = convert(v1);
}

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
    HANDLE  f;
    SIZE_T  payload_len, alloc_size, remainder;
    DWORD   nread;

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
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len + BLOCKSIZEB);

    // read the shellcode
    memset(payload, 0x90, alloc_size);
    ReadFile(f, payload, payload_len, &nread, NULL);

    // encrypt data, 
    memcpy (&payload[alloc_size], iv, BLOCKSIZEB);
    encrypt (payload, alloc_size, key, iv);

    // print
    print_hex("IV", iv, BLOCKSIZEB);
    print_hex("Payload", payload, alloc_size + BLOCKSIZEB);

    // destroy heap
    HeapFree (GetProcessHeap(), 0, payload);

    return 0;
}