/*
    Generator
    substitute with Bit Inverse

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerator.cpp 
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void substitute (uint8_t * dst, uint8_t * src, size_t size)
{
    for (size_t idx=0; idx<size; idx++) {
        dst[idx] = ~src[idx];
    }
}


int main()
{
    HANDLE  f;
    SIZE_T  payload_len;
    DWORD   nread;

    uint8_t  *  payload;
    uint32_t    idx;


    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len);

    // read the shellcode
    ReadFile(f, payload, payload_len, &nread, NULL);

    // encode by substitute it with inverted bits.
    substitute(payload, payload, payload_len);

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