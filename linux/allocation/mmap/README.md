# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `mmap`.

```c++
#include <sys/mman.h>

void *mmap(void addr, size_t length, int prot, int flags, int fd, off_t offset);

int munmap(void addr, size_t length);
```

### Reference

- [Man 7](https://man7.org/linux/man-pages/man2/mmap.2.html)