# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `valloc`. Fungsi `valloc` bekerja dengan mengalokasikan block memory yang dimulai dari alamat kelipatan page. Secara teknis `valloc` sama dengan `memalign(sysconf(_SC_PAGESIZE), size)`.

Fungsi `valloc` mirip dengan `pvalloc` (lib `malloc.h`). Perbedaannya adalah `pvalloc` akan melakukan pembulatan size menjadi kelipatan dari ukuran page.

Sebagai catatan, `valloc` berstatus legacy dan digantikan dengan `aligned_alloc`.

```c++
#include <stdlib.h>

void * valloc(size_t size);
```

### Reference

- [Man 3](https://linux.die.net/man/3/valloc)