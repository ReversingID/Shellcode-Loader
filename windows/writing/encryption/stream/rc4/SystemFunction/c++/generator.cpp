/*
    Generator
    Encryption with RC4 using internal function SystemFunction032/SystemFunction033

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerator.cpp
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib,"advapi32")

#define KEY_SIZE    32

/* ========= some definition ========= */
typedef struct
{
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} ustring;

/* ========= function signatures ========= */
typedef NTSTATUS NTAPI SystemFunction032_t (ustring* data, ustring* key);
typedef SystemFunction032_t FAR * pSystemFunction032;


void encrypt (uint8_t* data, uint32_t size, uint8_t key_buf[KEY_SIZE])
{
    ustring payload;
    ustring key;

    payload.Length = size;
    payload.Buffer = data;

    key.Length = KEY_SIZE;
    key.Buffer = key_buf;

    HMODULE lib = LoadLibrary("advapi32.dll");
    pSystemFunction032 SystemFunction032 = (pSystemFunction032) GetProcAddress(lib, "SystemFunction032");

    SystemFunction032(&payload, &key);
}


int main()
{
    HANDLE  f;
    SIZE_T  payload_len;
    DWORD   nread;

    uint8_t * payload;
    uint8_t   key[] = "Reversing.ID_ShellcodeLoader1337";
    uint32_t  idx;

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * payload_len);

    // read the shellcode
    ReadFile (f, payload, payload_len, &nread, NULL);

    // encrypt the shellcode
    encrypt (payload, payload_len, key);

    // print
    printf("%lld\n", sizeof(key));
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