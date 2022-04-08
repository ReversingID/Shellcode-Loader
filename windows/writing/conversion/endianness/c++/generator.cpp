/*
    Generator
    Convert endianness from little-endian to big-endian.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp 

Note:
    - operating 64-bit number with htonll
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdint.h>
#include <stdio.h>

#pragma comment(lib,"ws2_32")

int main()
{
    HANDLE  f;
    SIZE_T  payload_len;
    DWORD   nread;

    uint8_t * payload;

    int idx, nitem = 0;
    SIZE_T  remainder, multiple = 8;

    uint64_t * ptr;

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    remainder   = payload_len % multiple;
    if (remainder)
    {
        payload_len += (multiple - remainder);
    }
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len);

    // read the shellcode
    ReadFile(f, payload, payload_len, &nread, NULL);

    ptr = (uint64_t*)payload;

    // print
    for (idx = 0; idx < payload_len; idx += multiple, nitem++)
    {
        ptr[nitem] = htonll(ptr[nitem]);

        printf("  \"");
        for (size_t j = 0; j < 8; j++)
            printf("\\x%02x", payload[idx + j]);
        printf("\"\n");
    }

    printf ("Item: %d | Length: %lld bytes\n", nitem, payload_len);

    // destroy heap
    HeapFree (GetProcessHeap(), 0, payload);

    return 0;
}