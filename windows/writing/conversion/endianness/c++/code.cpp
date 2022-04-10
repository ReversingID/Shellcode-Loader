/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    ntohll
    - permission: VirtualProtect
    - execution:  CreateThread

Note:
    - operating 64-bit number with ntohll
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdint.h>

#pragma comment(lib,"ws2_32")


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = "\x00\x00\x00\x00\xc3\xcc\x90\x90";
    uint32_t    nitem       = 1;

    uint64_t *  ptr_src;
    uint64_t *  ptr_dst;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, nitem * 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    ptr_src = (uint64_t *)payload;
    ptr_dst = (uint64_t *)runtime;

    for (uint32_t idx = 0; idx < nitem; idx++)
    {
        ptr_dst[idx] = ntohll(ptr_src[idx]);
    }

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, nitem * 8, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}