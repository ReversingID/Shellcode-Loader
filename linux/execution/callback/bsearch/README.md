# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `bsearch` (glibc).

Fungsi `bsearch` mengimplementasikan pencarian elemen pada array terurut menggunakan algoritma binary search.

```c++
#include <stdlib.h>

typedef void (*callback_t)(const void *, const void *);

void* bsearch(const void *key, const void * base, size_t length, size_t size, callback_t comparator);
```

Dalam proses pencarian, callback comparator akan dipanggil untuk setiap elmeen. Callback ini dapat di-abuse untuk melakukan eksekusi shellcode.

### Reference

- [Man 3](https://man7.org/linux/man-pages/man3/bsearch.3.html)