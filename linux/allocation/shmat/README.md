# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `shmat`. Fungsi `valloc` mengalokasikan shared memory segment.

```c++
#include <sys/types.h>
#include <sys/shm.h>

void * shmat(int shmid, const void * shmaddr, int shmflg);
```

### Reference

- [Man 2](https://linux.die.net/man/2/shmat)