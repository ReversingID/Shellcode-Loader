# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `qsort` (glibc).

Fungsi `qsort` mengimplementasikan pengurutan elemen array (sorting) menggunakan algoritma quick sort.

```c++
#include <stdlib.h>

typedef void (*callback_t)(const void *, const void *);

void qsort(void * base, size_t length, size_t size, callback_t comparator);
```

Dalam proses pengurutan, callback comparator akan dipanggil untuk setiap perbandingkan dua elemen. Callback ini dapat di-abuse untuk melakukan eksekusi shellcode.

### Reference

- [Man 3](https://man7.org/linux/man-pages/man3/qsort.3.html)