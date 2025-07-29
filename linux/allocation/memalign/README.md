# Shellcode Loader

Allocate memory for executing shellcode later.

### Overview

Alokasi menggunakan `memalign`. Fungsi `pvalloc` bekerja dengan mengalokasikan block memory yang dimulai dari alamat kelipatan page.

Fungsi `pvalloc` mirip dengan `valloc` (lib `stdlib.h`). Perbedaannya adalah `pvalloc` akan melakukan pembulatan size menjadi kelipatan dari ukuran page.

Sebagai catatan, `pvalloc` berstatus legacy dan digantikan dengan `memalign`.

```c++
#include <malloc.h>

void * pvalloc(size_t size);
```

### Reference

- [Man 3](https://linux.die.net/man/3/pvalloc)