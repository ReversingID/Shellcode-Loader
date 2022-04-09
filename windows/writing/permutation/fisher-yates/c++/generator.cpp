/*
    Generator
    Permutation with Fisher-Yates Shuffle.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcgenerate.cpp 

Note:
    - operating 64-bit number with htonll
*/

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void permutation (uint32_t index[], uint32_t size, uint32_t seed)
{
    uint32_t temp;

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


int main()
{
    HANDLE  f;
    SIZE_T  payload_len;
    DWORD   nread;

    uint8_t  *  payload;
    uint32_t *  indexes;
    uint32_t    idx;
    uint32_t    seed = 0x1337;
    uint32_t *  ptr;


    // open existing file
    f = CreateFile ("shellcode.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // query the size and create enough space in heap
    payload_len = GetFileSize (f, NULL);
    payload = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len + sizeof(seed));
    ptr     = (uint32_t*)payload;
    *ptr    = seed;

    // read the shellcode
    ReadFile(f, payload + sizeof(seed), payload_len, &nread, NULL);

    // generate array of index
    indexes = (uint32_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len * sizeof(uint32_t));
    for (idx = 0; idx < payload_len; idx++) indexes[idx] = idx;

    permutation(indexes, payload_len, seed);

    // print
    printf("{\n  ");
    for (idx = 0; idx < sizeof(seed); idx++)
    {
        printf("0x%02x, ", payload[idx]);
    }
    payload += sizeof(seed);
    for (idx = 0; idx < payload_len; idx++)
    {
        if (idx % 16 == 0)
            printf("\n  ");
        
        printf("0x%02x, ", payload[indexes[idx]]);
    }
    printf("\n}\n");

    printf ("Length: %lld\n", payload_len + sizeof(seed));

    // destroy heap
    HeapFree (GetProcessHeap(), 0, indexes);
    HeapFree (GetProcessHeap(), 0, payload - sizeof(seed));

    return 0;
}