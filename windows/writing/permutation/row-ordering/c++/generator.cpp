/*
    Generator
    Create matrix of shellcode and reordering the row

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp 
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

struct header_t
{
    uint32_t row;
    uint32_t seed;
};

// Permutation with Fisher-Yates Shuffle algorithm.
void permutation (uint8_t index[], uint32_t size, uint32_t seed)
{
    uint8_t temp;

    // seed the random generator
    // alternative: use mersenne twister
    srand (seed);

    // start from the last element and swap one by one
    for (int i = size-1; i > 0; i--)
    {
        // pick random index from 0 to 1
        int j = rand() % (i + 1);

        // swap index[i] with the element at random index
        temp = index[i];
        index[i] = index[j];
        index[j] = temp;
    }
}

void encode (uint8_t * dst, uint8_t * src, uint32_t size)
{
    uint8_t * indexes;
    uint32_t column;
    uint32_t idx_r, idx_c, idx_d;
    header_t * header;

    // assume size is multiple of row
    header = (header_t*)dst;
    column = size / header->row;

    // generate index for row reordering
    indexes = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, header->row);
    for (idx_r = 0; idx_r < header->row; idx_r++) indexes[idx_r] = idx_r;
    permutation(indexes, header->row, header->seed);

    // reordering
    dst += sizeof(header_t);
    for (idx_c = 0, idx_d = 0; idx_c < column; idx_c ++)
    {
        for (idx_r = 0; idx_r < header->row; idx_r++, idx_d++)
        {
            dst[idx_d] = src[indexes[idx_r] * column + idx_c];
        }
    }

    HeapFree (GetProcessHeap(), 0, indexes);
}

int main()
{
    HANDLE  f;
    SIZE_T  payload_len;
    DWORD   nread;

    // uint8_t  *  payload;
    uint8_t  *  payload;
    uint8_t  *  runtime;
    uint32_t    idx;
    header_t    header;
    uint32_t    remainder;

    // generate random row
    srand(time(NULL));
    header.seed = 0x1337;
    header.row  = rand() % 6 + 4;

    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    remainder   = payload_len % header.row;
    if (remainder)
        payload_len += (header.row - remainder);

    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len);
    runtime = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len + sizeof(header));

    // read the shellcode
    ReadFile(f, payload, payload_len, &nread, NULL);

    // encode
    *(header_t*)runtime = header;
    encode(runtime, payload, payload_len);

    // print
    printf("{\n  ");
    for (idx = 0; idx < sizeof(header); idx++)
    {
        printf("0x%02x, ", runtime[idx]);
    }
    runtime += sizeof(header);
    for (idx = 0; idx < payload_len; idx++)
    {
        if (idx % 16 == 0)
            printf("\n  ");
        
        printf("0x%02x, ", runtime[idx]);
    }
    printf("\n}\n");
    printf ("Length: %lld\n", payload_len + sizeof(header));

    // destroy heap
    HeapFree (GetProcessHeap(), 0, runtime - sizeof(header));
    HeapFree (GetProcessHeap(), 0, payload);

    return 0;
}