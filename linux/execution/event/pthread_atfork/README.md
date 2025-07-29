# Shellcode Loader

Executing shellcode at fork.

### Overview

Daftarkan shellcode dengan handler `pthread_atfork` sehingga eksekusi secara otomatis saat fork terjadi.

```sh
#include <pthread.h>

typedef void (*callback_t)(void);

int pthread_atfork(callback_t prepare, callback_t parent, callback_t child);
```

Terdapat tiga handle yang bisa digunakan:
- prepare: dieksekusi di parent process sesaat sebelum `fork` terjadi
- parent: dieksekusi di parent process setelah `fork` selesai.
- child: dieksekusi di child process setelah `fork` selesai.

### Reference

- [Man 3](https://man7.org/linux/man-pages/man3/pthread_atfork.3.html)