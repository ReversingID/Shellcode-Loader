/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode with fork handler (pthread_atfork).

Compile:
    $ g++ code.cpp -pthread

Technique:
    - allocation: mmap
    - writing:    memcpy
    - permission: mprotect
    - execution:  pthread_atfork
*/

#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>

typedef void (*callback_t)(void);

#include <stdio.h>
void prepare(void)
{
    printf("[!] on stage prepare\n");
}

void parent(void)
{
    printf("[!] on stage parent\n");
}

void child(void)
{
    printf("[!] on stage child\n");
}

int main ()
{
    void *      runtime;
    int         retval;
    pid_t       pid;

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
        // register to pthread_atfork
        // there are 3 different handlers that can be abused.
        // this example will run before fork happen and other handlers are disabled.
        // pthread_atfork((callback_t)runtime, NULL, NULL);
        pthread_atfork(prepare, parent, child);
    }

    // deallocate might be unnecessary, depend on the case
    
    // can do anything here before fork happen
    if ((pid = fork()) == 0)
    {
        // child process
    }
    else
    {
        // parent process
    }

    return 0;
}