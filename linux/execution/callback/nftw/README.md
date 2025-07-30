# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `nftw` (glibc).

Fungsi `nftw` adalah fungsi POSIX yang digunakan untuk menelusuri file yang ada pada sebuah direktori. Callback akan dipanggil untuk setiap file yang ditemukan.

Fungsi `nftw` adalah fungsi pengganti ftw yang saat ini berstatus deprecated.

```c++
#include <ftw.h>

typedef int (*callback_t)(const char *, const struct stat *, int, struct FTW *);

int nftw(const char * dirpath, callback_t callback, int openfd, int flags);
```

### Reference

- [Man 3](https://man7.org/linux/man-pages/man3/nftw.3.html)