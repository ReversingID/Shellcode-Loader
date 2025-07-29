# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `posix_memalign`. Fungsi `posix_memalign` bekerja dengan mengalokasikan block memory yang dimulai dari alamat kelipatan page.

```c++
#include <stdlib.h>

int posix_memalign(void **memptr, size_t alignment, size_t size);
```

### Reference

- [Man 3](https://linux.die.net/man/3/posix_memalign)