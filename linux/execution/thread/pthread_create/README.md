# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan `pthread_create` and tunggu hingga eksekusi tuntas dengan `pthread_join`.

```c++
#include <pthread.h>

typedef void* (*entrypoint_t)(void*);

int pthread_create(pthread_t * thread, const pthread_attr_t * attr, entrypoint_t start_routine, void * arg);

int pthread_join(pthread_t thread, void ** retval);
```

### Reference

- [Man 3 pthread_create](https://man7.org/linux/man-pages/man3/pthread_create.3.html)
- [Man 3 pthread_join](https://man7.org/linux/man-pages/man3/pthread_join.3.html)