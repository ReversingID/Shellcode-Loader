/*
    Generator
    substitution with Hill Cipher

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp 
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// multiply 2x2 with 2x1 matrix
void multiply(uint8_t * dst, uint8_t * src, uint8_t key[2][2]) {
    // iterate row
    for (size_t idx=0; idx<2; idx++) {
        dst[idx] = (key[idx][0]*src[0] + key[idx][1]*src[1]) % 256;
    }
}

// 2x2 matrix as key and array of 2 elements as input
void substitution (uint8_t * dst, uint8_t * src, uint8_t key[2][2], size_t size)
{
    for (size_t idx=0; idx<size; idx+=2) {
        // matrix multiplication
        multiply(&dst[idx], &src[idx], key);
    }
}


int main()
{
    HANDLE  f;
    SIZE_T  payload_len, fsize;
    DWORD   nread;

    // |193    0|
    // |  0  173|
    uint8_t key[2][2] = { {197, 0}, {0, 173} };

    uint8_t  *  payload;
    uint32_t    idx;

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    fsize = GetFileSize (f, NULL);
    // make sure the length is multiple of 2
    payload_len = fsize + (fsize % 2);
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, fsize);

    // read the shellcode
    ReadFile(f, payload, fsize, &nread, NULL);
 
    substitution(payload, payload, key, payload_len);

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