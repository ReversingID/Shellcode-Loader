/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode by raising signal.

Compile:
    $ g++ code.cpp

Technique:
    - allocation: mmap
    - writing:    memcpy
    - permission: mprotect
    - execution:  signal
*/

#include <sys/mman.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef void (*callback_t)(int);

int main ()
{
    void *      runtime;
    int         retval;

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
        // register the signal handler
        signal(SIGUSR1, (callback_t)runtime);
        raise(SIGUSR1);
    }

    // deallocate memory map
    munmap (runtime, payload_len);

    return 0;
}