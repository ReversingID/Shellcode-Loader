# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `ftw` (glibc).

Fungsi `ftw` adalah fungsi POSIX yang digunakan untuk menelusuri file yang ada pada sebuah direktori. Callback akan dipanggil untuk setiap file yang ditemukan. 

```c++
#include <ftw.h>

typedef int (*callback_t)(const char *, const struct stat *, int);

int ftw(const char * dirpath, callback_t callback, int openfd);
```

### Reference

- [Man 3](https://man7.org/linux/man-pages/man3/ftw.3.html)