/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new thread.

Compile:
    $ g++ code.cpp -pthread

Technique:
    - allocation: mmap
    - writing:    memcpy
    - permission: mprotect
    - execution:  clone + invoke
*/

#include <sys/mman.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

// allocate 1MB for the stack
#define STACK_SIZE (1024 * 1024)

// struct for arguments
struct thread_args_t
{
    void *  code;
    int     notify;
};


// entrypoint for the thread
int entrypoint (void * arg)
{
    thread_args_t * data = (thread_args_t *) arg;

    /*
    we need to invoke shellcode manually because we need to
    notify main thread over the pipe.
    */
    void (*sc)() = (void(*)()) data->code;
    sc();

    // notify main thread to resume operation
    uint8_t done = 1;
    write(data->notify, &done, sizeof(done));

    return 0;
}

int main ()
{
    void *      runtime;
    void *      stack;
    void *      stack_top;
    int         retval;

    // shellcode storage in stack
    uint8_t     payload []  = { 0x90, 0x90, 0xCC, 0xC3 };
    uint32_t    payload_len = 4;
    uint32_t    flags, tid;
    uint8_t     done;

    // allocate memory buffer for payload as READ-WRITE (no executable)
    runtime = mmap (0, payload_len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    // copy payload to the buffer
    memcpy (runtime, payload, payload_len);

    // make buffer executable (R-X)
    retval  = mprotect (runtime, payload_len, PROT_READ|PROT_EXEC);

    if (retval == 0)
    {
        // use pipe to act as thread-join signal later
        int pipefd[2];
        pipe(pipefd);

        // create argument to the thread
        thread_args_t args = { 
            .code   = runtime, 
            .notify = pipefd[1] 
        };

        // create stack for the thread
        stack = mmap (0, STACK_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_STACK, -1, 0);
        stack_top = (char*)stack + STACK_SIZE;

        /*
        create new thread
        
        Flags:
            CLONE_VM:      share virtual memory space with the parent
            CLONE_FS:      share file system information (current working directory, umask, etc)
            CLONE_FILES:   share file descriptors (open files)
            CLONE_SIGHAND: share signal handlers
            CLONE_PARENT:  share parent process
            CLONE_THREAD:  create thread belongs to the same thread group as the parent (sharing the same PID)
            CLONE_IO:      share I/O resources
        */
        flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_PARENT | CLONE_THREAD | CLONE_IO;
        tid = clone (entrypoint, stack_top, flags, &args);

        // wait the thread to finish
        done = 0;
        read(pipefd[0], &done, 1);
    }

    // dealocate memory map
    munmap (runtime, payload_len);
    munmap (stack, STACK_SIZE);

    return 0;
}