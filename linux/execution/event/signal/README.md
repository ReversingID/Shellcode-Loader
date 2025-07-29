# Shellcode Loader

Executing shellcode by raising signal.

### Overview

Daftarkan shellcode ke sebuah signal tertentu dengan `signal` dan eksekusi dengan memicu signal yang sesuai.

Gunakan signal yang umum terjadi seperti: SIGUSR1, SIGUSR2, SIGCHLD. Hindari memicu signal mencurigakan seperti SIGSEGV, SIGILL, dsb.

```c++
#include <signal.h>

typedef void (*callback_t)(int);

callback_t signal(int signum, callback_t handler);
```

### Reference

- [Man 2](https://man7.org/linux/man-pages/man2/signal.2.html)