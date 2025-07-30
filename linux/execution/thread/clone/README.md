# Shellcode Loader

Executing shellcode as a thread.

### Overview

Eksekusi shellcode dengan syscall `clone`. Syscall `clone` digunakan untuk membuat process baru (oleh `fork`) ataupun thread baru (oleh `pthread_create`).

```c++
#include <sched.h>

typedef int (*callback_t)(void);

int clone(callback_t fn, void * stack, int flags, void * arg);
```

### Reference

- [Man 2 clone](https://man7.org/linux/man-pages/man2/clone.2.html)