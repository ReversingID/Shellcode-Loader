# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `scandir` (glibc).

Fungsi `scandir` adalah fungsi POSIX yang digunakan untuk memindai (scan) isi dari sebuah direktori. Terdapat dua buah callback yang dapat digunakan:

- `filter` untuk menentukan apakah entry layak / memenuhi kriteria.
- `compare` untuk mengurutkan entry.

```c++
#include <dirent.h>

typedef int (*cb_filter_t)(const struct dirent *);
typedef int (*cb_compare_t)(const struct dirent **, const struct dirent **);

int scandir (const char * dirp, struct dirent *** result, cb_filter_t filter, cb_compare_t compare);
```

### Reference

- [Man 3](https://man7.org/linux/man-pages/man3/scandir.3.html)