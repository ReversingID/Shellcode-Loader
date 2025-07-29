# Shellcode Loader

Executing shellcode at process exit.

### Overview

Daftarkan shellcode dengan `atexit` sehingga eksekusi secara otomatis tepat sebelum process berakhir.

`atexit` adalah handler yang digunakan untuk melakukan cleanup (pembersihan resource), atau terminasi segala aktivitas lain. Fungsi ini adalah fungsi standard di standard library C sehingga dapat pula diterapkan pada platform lain.

```c++
#include <stdlib.h>

int atexit(void (*func)(void));
```

### Reference

- [Linux Man 3](https://man7.org/linux/man-pages/man3/atexit.3.html)
- [C++ Reference](http://en.cppreference.com/w/c/program/atexit)