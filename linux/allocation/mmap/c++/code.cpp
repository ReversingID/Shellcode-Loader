/*
    Shellcode Loader
    Archive of Reversing.ID

    allocate memory with mmap

Compile:
    $ g++ code.cpp -pthread

Technique:
    - allocation: mmap
    - writing:    memcpy
    - permission: mprotect
    - execution:  pthread_create
*/

#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

typedef void* (*thread_entrypoint)(void*);

int main ()
{
    void *      runtime;
    int         retval;
    pthread_t   th_shellcode;

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
        // execute as new thread
        pthread_create (&th_shellcode, NULL, (thread_entrypoint)runtime, NULL);
        pthread_join (th_shellcode, NULL);
    }

    // dealocate memory map
    munmap (runtime, payload_len);

    return 0;
}