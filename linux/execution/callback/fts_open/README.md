# Shellcode Loader

Abusing callback to run shellcode.

### Overview

Eksekusi shellcode dengan `fts_open` dan `fts_read` (glibc).

Fungsi `fts_open` dan `fts_read` adalah bagian dari pustaka FTS (File Tree Scan) dan didesain untuk menelusuri hirarki file. Pustaka ini bukan bagian dari libc standard namun diimplementasikan dalam banyak UNIX-like operating system.

FTS adalah layer abstraksi dari `opendir` dan `readdir` secara rekursif untuk menelusuri tree. Callback digunakan untuk mengurutkan file.

```c++
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

typedef int (*callback_t)(const FTSENT **, const FTSENT **);

FTS * fts_open (char * const * path_argv, int options, callback_t comparator);
```

Meski digunakan oleh `fts_open` tapi callback hanya akan dijalankan ketika `fts_read` digunakan untuk menelusuri path.

### Reference

- [Man 3 fts_open](https://linux.die.net/man/3/fts_open)
- [Man 3 fts_read](https://linux.die.net/man/3/fts_read)